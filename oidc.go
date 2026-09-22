package idauth

import (
	"context"
	"errors"
	"net/url"

	"github.com/lx-lib/lx-idauth/core"

	"azugo.io/azugo"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type OidcAuthProvider struct {
	auth          *IDAuth
	config        *core.AuthProviderConfig
	oauth2Config  oauth2.Config
	provider      *oidc.Provider
	claimMapper   *jsonnetClaimMapper
	endSessionURL string
	signoutURL    string
}

func NewOidcService(auth *IDAuth, conf *core.AuthProviderConfig) (*OidcAuthProvider, error) {
	provider, err := oidc.NewProvider(context.Background(), conf.MetadataURL)
	if err != nil {
		return nil, err
	}

	var claimMapper *jsonnetClaimMapper
	if conf.ClaimMappingFile != "" {
		claimMapper, err = newJSONNetClaimMapper(conf.ClaimMappingFile)
		if err != nil {
			return nil, err
		}
	}

	scope := conf.Scope
	if len(scope) == 0 {
		scope = []string{oidc.ScopeOpenID, "profile", "email"}
	}

	oauth2Config := oauth2.Config{
		ClientID:     conf.ClientID,
		ClientSecret: conf.ClientSecret,
		Endpoint:     provider.Endpoint(),
		Scopes:       scope,
	}

	var discovery struct {
		EndSessionEndpoint string `json:"end_session_endpoint"`
	}
	_ = provider.Claims(&discovery)

	return &OidcAuthProvider{
		auth:          auth,
		config:        conf,
		oauth2Config:  oauth2Config,
		provider:      provider,
		claimMapper:   claimMapper,
		endSessionURL: discovery.EndSessionEndpoint,
	}, nil
}

func (p *OidcAuthProvider) Authorize(ctx *azugo.Context, cor *core.Correlation) error {
	p.oauth2Config.RedirectURL = ctx.BaseURL() + "/callback/" + p.config.ID
	url := p.oauth2Config.AuthCodeURL(*cor.State)
	if p.config.AcrValues != "" {
		url += "&acr_values=" + p.config.AcrValues
	}
	ctx.RedirectUnsafe(url)
	return nil
}

func (p *OidcAuthProvider) Callback(ctx *azugo.Context, sess *core.Correlation) (*core.AuthRequest, error) {
	code, err := ctx.Query.String("code")
	if err != nil {
		return nil, err
	}

	p.oauth2Config.RedirectURL = ctx.BaseURL() + "/callback/" + p.config.ID

	oauth2Token, err := p.oauth2Config.Exchange(ctx, code)
	if err != nil {
		return nil, err
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return nil, errors.New("missing id_token")
	}

	idToken, err := p.provider.
		Verifier(&oidc.Config{ClientID: p.oauth2Config.ClientID}).
		Verify(ctx, rawIDToken)
	if err != nil {
		return nil, err
	}

	if sess.Nonce != nil && *sess.Nonce != idToken.Nonce {
		return nil, errors.New("nonce did not match")
	}

	if p.config.PostCallbackSignout {
		p.signoutURL = p.buildEndSessionURL(rawIDToken, ctx.BaseURL()+"/oidc/logout/callback")
	}

	var allClaims map[string]any
	if err := idToken.Claims(&allClaims); err != nil {
		return nil, err
	}

	if p.claimMapper != nil {
		return p.claimMapper.mapToAuthRequest(ctx, &ClaimMappingInput{
			ProviderID:   p.config.ID,
			ProviderType: p.config.Type,
			Claims:       allClaims,
			Metadata:     p.config.Metadata,
			Nonce:        sess.Nonce,
			RawToken:     rawIDToken,
		})
	}

	var claims struct {
		Subject    string `json:"sub"`
		Email      string `json:"email"`
		GivenName  string `json:"given_name"`
		FirstName  string `json:"first_name"`
		FamilyName string `json:"family_name"`
		PersonCode string `json:"person_code"`
		LastName   string `json:"last_name"`
		Verified   bool   `json:"email_verified"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return nil, err
	}

	firstName := claims.GivenName
	if firstName == "" {
		firstName = claims.FirstName
	}

	lastName := claims.FamilyName
	if lastName == "" {
		lastName = claims.LastName
	}

	personCode := claims.PersonCode
	if personCode == "" {
		personCode = claims.Subject
	}

	return &core.AuthRequest{
		FirstName:  firstName,
		LastName:   lastName,
		Email:      claims.Email,
		Token:      rawIDToken,
		PersonCode: personCode,
		ProviderID: p.config.ID,
	}, nil
}

func (p *OidcAuthProvider) buildEndSessionURL(idTokenHint, postLogoutRedirectURI string) string {
	if p.endSessionURL == "" || idTokenHint == "" {
		return ""
	}

	u, err := url.Parse(p.endSessionURL)
	if err != nil {
		return ""
	}

	q := u.Query()
	q.Set("id_token_hint", idTokenHint)

	if postLogoutRedirectURI != "" {
		q.Set("post_logout_redirect_uri", postLogoutRedirectURI)
		q.Set("client_id", p.config.ClientID)
	}

	for k, v := range p.config.LogoutParams {
		q.Set(k, v)
	}

	u.RawQuery = q.Encode()

	return u.String()
}

func (p *OidcAuthProvider) LogoutURL(idTokenHint string) string {
	return p.buildEndSessionURL(idTokenHint, p.config.PostLogoutRedirectURI)
}

// implementē core.ProviderCallbackSignout.
func (p *OidcAuthProvider) GetSignoutURL() string {
	return p.signoutURL
}

// implementē core.ProviderCallbackSignout.
func (p *OidcAuthProvider) RequiresSignoutCallback() bool {
	return p.config.PostCallbackSignout
}
