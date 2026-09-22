package idauth

import (
	"net/url"
	"time"

	"github.com/lx-lib/lx-idauth/core"

	"azugo.io/azugo"
)

// OAuthConfiguration response.
type OAuthConfiguration struct {
	// Issuer of the token.
	Issuer string `json:"issuer,omitempty"`
	// GrantTypesSupported is the list of supported grant types.
	GrantTypesSupported []string `json:"grant_types_supported,omitempty"`
	// ResponseTypesSupported
	ResponseTypesSupported []string `json:"response_types_supported,omitempty"`
	// TokenEndpoint is the URL to use to get a token.
	TokenEndpoint string `json:"token_endpoint,omitempty"`
	// UserInfoEndpoint is the URL to use to get current authorize user information.
	UserInfoEndpoint string `json:"userinfo_endpoint,omitempty"`
	// TokenEndpointAuthMethodsSupported is the list of supported authentication methods.
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported,omitempty"`
}

type ConfigResponse struct {
	SessionTimeout   time.Duration `json:"session_timeout"`
	SessionCountdown time.Duration `json:"session_countdown"`
}

func (a *IDAuth) metadata() azugo.RequestHandler {
	return func(ctx *azugo.Context) {
		basePath := ctx.BaseURL()

		tokenEndpoint, err := url.JoinPath(basePath, "/token")
		if err != nil {
			ctx.Error(err)
			return
		}

		userInfoEndpoint, err := url.JoinPath(basePath, "/userinfo")
		if err != nil {
			ctx.Error(err)
			return
		}

		grantTypesSupported := []string{"client_credentials"}
		responseTypesSupported := []string{}
		tokenEndpointAuthMethodsSupported := []string{"client_secret_basic"}

		if a.config.ExposedConfig().UsesAuthorizationCodeGrant {
			grantTypesSupported = append(grantTypesSupported, "authorization_code")
			responseTypesSupported = append(responseTypesSupported, "code")
			tokenEndpointAuthMethodsSupported = append(tokenEndpointAuthMethodsSupported, "none")
		}

		if a.config.ExposedConfig().UsesIAMGrant {
			grantTypesSupported = append(grantTypesSupported, core.GRANT_TYPE_IAM)
		}

		if a.config.ExposedConfig().UsesPfasGrant {
			grantTypesSupported = append(grantTypesSupported, "pfas")
		}

		ctx.JSON(&OAuthConfiguration{
			Issuer:                            ctx.BaseURL(),
			TokenEndpoint:                     tokenEndpoint,
			UserInfoEndpoint:                  userInfoEndpoint,
			GrantTypesSupported:               grantTypesSupported,
			ResponseTypesSupported:            responseTypesSupported,
			TokenEndpointAuthMethodsSupported: tokenEndpointAuthMethodsSupported,
		})
	}
}

func (a *IDAuth) getConfigValues(ctx *azugo.Context) {
	ctx.JSON(&ConfigResponse{
		SessionTimeout:   time.Duration(a.config.ExposedConfig().SessionTimeout.Seconds()),
		SessionCountdown: time.Duration(a.config.ExposedConfig().SessionCountdown.Seconds()),
	})
}
