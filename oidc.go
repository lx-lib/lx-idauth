package idauth

import (
	"context"
	"errors"

	"github.com/nobid-lsp-latvia/lx-idauth/core"

	"azugo.io/azugo"
	oidc "github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

type OidcAuthProvider struct {
	auth         *IDAuth
	config       *core.AuthProviderConfig
	oauth2Config oauth2.Config
	provider     *oidc.Provider
}

func NewOidcService(auth *IDAuth, conf *core.AuthProviderConfig) (*OidcAuthProvider, error) {
	provider, err := oidc.NewProvider(context.Background(), conf.MetadataURL)
	if err != nil {
		return nil, err
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

	return &OidcAuthProvider{
		auth:         auth,
		config:       conf,
		oauth2Config: oauth2Config,
		provider:     provider,
	}, nil
}

func (p *OidcAuthProvider) Authorize(ctx *azugo.Context, cor *core.Correlation) error {
	p.oauth2Config.RedirectURL = ctx.BaseURL() + "/callback/" + p.config.ID
	url := p.oauth2Config.AuthCodeURL(*cor.State)
	if p.config.AcrValues != "" {
		url += "&acr_values=" + p.config.AcrValues
	}
	ctx.Redirect(url)
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

	var claims struct {
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

	return &core.AuthRequest{
		FirstName:  firstName,
		LastName:   lastName,
		Email:      claims.Email,
		Token:      rawIDToken,
		PersonCode: claims.PersonCode,
	}, nil
}
