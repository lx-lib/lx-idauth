package core

import (
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/nobid-lsp-latvia/lx-idauth/core/auth"

	"azugo.io/azugo"
	"github.com/valyala/fasthttp"
)

const (
	AuthorizationBearer = "bearer"

	TOKEN_TYPE_BASIC = "basic"
	TOKEN_TYPE_PFAS  = "pfas"
)

type TokenValidationResult struct {
	Valid        bool
	ClientID     string
	ClientSecret *string // sha512
	ClientName   *string
	LegalEntity  *string
}

type TokenValidator interface {
	ValidateToken(ctx *azugo.Context) (*TokenValidationResult, error)
}

func NewTokenValidator(tokenType string, clientStore ClientStore, pfasConfig *PfasAuthTokenValidatorConfig) TokenValidator {
	switch tokenType {
	case TOKEN_TYPE_BASIC:
		return &BasicAuthTokenValidator{
			clientStore: clientStore,
		}
	case TOKEN_TYPE_PFAS:
		return &PfasAuthTokenValidator{
			clientStore: clientStore,
			config:      pfasConfig,
		}
	default:
		return &NoopTokenValidator{}
	}
}

type BasicAuthTokenValidator struct {
	clientStore ClientStore
}

func (v *BasicAuthTokenValidator) ValidateToken(ctx *azugo.Context) (*TokenValidationResult, error) {
	scope := ctx.Form.StringOptional("scope")
	clientID, clientSecret, err := v.getBasicAuthCredentials(ctx)
	if err != nil {
		ctx.StatusCode(fasthttp.StatusUnauthorized)
		return nil, err
	}

	hash := sha512.New()
	hash.Write([]byte(*clientSecret))
	hashedSecret := hex.EncodeToString(hash.Sum(nil))
	clientSecret = &hashedSecret

	if err := v.clientStore.ValidateCredentials(&ClientCredentials{
		ClientID:     *clientID,
		ClientSecret: clientSecret,
		Scope:        scope,
		GrantType:    TOKEN_TYPE_BASIC,
	}); err != nil {
		ctx.StatusCode(fasthttp.StatusUnauthorized)
		return nil, err
	}

	return &TokenValidationResult{
		Valid:        true,
		ClientID:     *clientID,
		ClientSecret: clientSecret,
	}, nil
}

func (v *BasicAuthTokenValidator) getBasicAuthCredentials(ctx *azugo.Context) (*string, *string, error) {
	decoded, err := base64.StdEncoding.DecodeString(parseBearerToken(ctx))
	if err != nil {
		return nil, nil, err
	}

	creds := strings.SplitN(string(decoded), ":", 2)
	if len(creds) != 2 {
		return nil, nil, errors.New("invalid authorization header")
	}

	return &creds[0], &creds[1], nil
}

type PfasAuthTokenValidatorConfig struct {
	IntrospectionURL          string `mapstructure:"introspection_url" validate:"required"`
	IntrospectionClientId     string `mapstructure:"introspection_client_id" validate:"required"`
	IntrospectionClientSecret string `mapstructure:"introspection_client_secret" validate:"required"`
}
type PfasAuthTokenValidator struct {
	clientStore ClientStore
	config      *PfasAuthTokenValidatorConfig
}

type IntrospectionResponse struct {
	Active       string `json:"active"`
	Scope        string `json:"scp"`
	ClientID     string `json:"client_id"`
	Username     string `json:"username"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"exp"`
	IssuedAt     int64  `json:"iat"`
	NotBefore    int64  `json:"nbf"`
	Subject      string `json:"sub"`
	Audience     string `json:"aud"`
	Issuer       string `json:"iss"`
	JwtId        string `json:"jti"`
	PrimarySid   string `json:"primarysid"`
	AuthTime     int64  `json:"auth_time"`
	LegalEntity  string `json:"legalentity"`
	NameIdFormat string `json:"nameidformat"`
	AuthMethod   string `json:"arm"`
}

func (v *PfasAuthTokenValidator) ValidateToken(ctx *azugo.Context) (*TokenValidationResult, error) {
	scope := ctx.Form.StringOptional("scope")
	token := parseBearerToken(ctx)
	if token == "" {
		return nil, &auth.AuthorizeError{
			Code:    auth.AuthErrNoToken,
			Message: "Missing authorization token",
		}
	}

	introspectionResp, err := v.introspectToken(ctx, token)
	if err != nil {
		ctx.StatusCode(fasthttp.StatusUnauthorized)
		return nil, &auth.AuthorizeError{
			Code:    auth.AuthErrInvalidToken,
			Message: "Invalid token",
		}
	}

	if scope != nil {
		requestedScopes := strings.Fields(*scope)
		availableScopes := strings.Fields(introspectionResp.Scope)
		for _, requestedScope := range requestedScopes {
			if !slices.Contains(availableScopes, requestedScope) {
				return nil, &auth.AuthorizeError{
					Code:    auth.AuthErrInvalidScope,
					Message: "Invalid scope",
				}
			}
		}
	}

	audienceArr := strings.Split(introspectionResp.Audience, ":") // urn:oauth2:00000000-0000-0000-0000-000000000000
	parsedClientID := audienceArr[len(audienceArr)-1]

	if err := v.clientStore.ValidateCredentials(&ClientCredentials{
		ClientID:     parsedClientID,
		ClientSecret: nil,
		Scope:        scope,
		GrantType:    TOKEN_TYPE_PFAS,
	}); err != nil {
		return nil, err
	}

	return &TokenValidationResult{
		Valid:       introspectionResp.Active == "true",
		ClientID:    parsedClientID,
		ClientName:  &introspectionResp.Username,
		LegalEntity: &introspectionResp.LegalEntity,
	}, nil
}

func (v *PfasAuthTokenValidator) introspectToken(ctx *azugo.Context, token string) (*IntrospectionResponse, error) {
	data := url.Values{}
	data.Set("token", token)

	parsedURL, err := url.Parse(v.config.IntrospectionURL)
	if err != nil {
		return nil, err
	}

	client := ctx.HTTPClient().WithBaseURL(parsedURL.Scheme + "://" + parsedURL.Host)
	req := client.NewRequest()
	if err := req.SetRequestURL(parsedURL.Path); err != nil {
		return nil, err
	}

	req.Header.SetMethod(fasthttp.MethodPost)
	defer client.ReleaseRequest(req)

	req.SetBodyString(data.Encode())
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(v.config.IntrospectionClientId+":"+v.config.IntrospectionClientSecret)))

	res := client.NewResponse()
	defer client.ReleaseResponse(res)

	if err := client.Do(req, res); err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	if res.StatusCode() != fasthttp.StatusOK {
		return nil, fmt.Errorf("introspection request failed with status code %d", res.StatusCode())
	}

	var introspectionResp IntrospectionResponse
	if err := json.Unmarshal(res.Body(), &introspectionResp); err != nil {
		return nil, fmt.Errorf("failed to parse introspection response: %w", err)
	}

	return &introspectionResp, nil
}

// Fallback no-op token validator. If token doesn't match any of the known types, it will be considered invalid.
type NoopTokenValidator struct{}

func (v *NoopTokenValidator) ValidateToken(ctx *azugo.Context) (*TokenValidationResult, error) {
	return &TokenValidationResult{
		Valid: false,
	}, nil
}

func parseBearerToken(ctx *azugo.Context) string {
	token := ctx.Header.Get("Authorization")
	if len(token) == 0 || strings.ToLower(token) == "bearer null" || !strings.HasPrefix(strings.ToLower(token), AuthorizationBearer) {
		return ""
	}

	return strings.TrimSpace(token[len(AuthorizationBearer):])
}
