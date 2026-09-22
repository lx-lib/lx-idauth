package core

import (
	"azugo.io/azugo"
)

type AuthProviderConfig struct {
	ID                    string            `yaml:"id" json:"id,omitempty"`
	Type                  string            `yaml:"type" json:"type,omitempty"`
	Realm                 string            `yaml:"realm" json:"realm"`                                                               // For WSFED
	MetadataURL           string            `yaml:"metadata_url" json:"metadataUrl"`                                                  // For WSFED
	IDPEndpoint           string            `yaml:"idp_endpoint" json:"idpEndpoint" validate:"omitempty,url"`                         // For WSFED
	SigningCertificatePEM string            `yaml:"signing_certificate_pem" json:"signingCertificatePem" validate:"omitempty,base64"` // For WSFED
	PostCallbackSignout   bool              `yaml:"post_callback_signout" json:"postCallbackSignout"`                                 // For WSFED and OIDC
	ClientID              string            `yaml:"client_id" json:"client_id,omitempty"`                                             // For OpenID
	ClientSecret          string            `yaml:"client_secret" json:"client_secret,omitempty"`                                     // For OpenID
	Metadata              map[string]string `yaml:"metadata" json:"metadata,omitempty"`
	Scope                 []string          `yaml:"scope" json:"scope,omitempty"`
	AcrValues             string            `yaml:"acr_values" json:"acr_values,omitempty"`
	ClaimMappingFile      string            `yaml:"claim_mapping_file" json:"claimMappingFile,omitempty"`
	PostLogoutRedirectURI string            `yaml:"post_logout_redirect_uri" json:"postLogoutRedirectUri,omitempty" validate:"omitempty,url"` // For OIDC RP-initiated logout
	LogoutParams          map[string]string `yaml:"logout_params" json:"logoutParams,omitempty"`                                              // Extra query params appended to the OIDC end_session URL (e.g. IDP-specific force_logout)
}

type AuthProviderStore interface {
	GetAvailableProviders(clientID string) ([]*AuthProviderConfig, error)
	GetProvider(id string) (*AuthProviderConfig, error)
	GetAllProviders() ([]*AuthProviderConfig, error)
}

type AuthProvider interface {
	AuthStarter
	AuthHandler
}

type AuthStarter interface {
	Authorize(ctx *azugo.Context, sess *Correlation) error
}

type AuthHandler interface {
	Callback(ctx *azugo.Context, sess *Correlation) (*AuthRequest, error)
}

type ProviderCallbackSignout interface {
	GetSignoutURL() string
	RequiresSignoutCallback() bool
}

// ProviderLogout is optionally implemented by auth providers that support
// RP-initiated logout at the upstream IDP. Returns empty string if logout
// cannot be initiated (missing token, IDP does not advertise end_session_endpoint).
type ProviderLogout interface {
	LogoutURL(idTokenHint string) string
}

type AuthUserOrganization struct {
	OrganizationCode string   `json:"org_code" example:"90123456789"`
	RoleCodes        []string `json:"role_codes,omitempty" example:"[\"administrator\",\"user\"]"`
}

type AuthRequest struct {
	// PersonCode is the person code of the authorized user.
	PersonCode string `json:"person_code"`
	// FirstName is the first name of the authorized user.
	FirstName string `json:"first_name"`
	// LastName is the last name of the authorized user.
	LastName string `json:"last_name"`
	// Email is the email of the authorized user.
	Email string `json:"email"`
	// IPAddress is the IP address of the user.
	IPAddress string `json:"ip_address"`
	// Nonce is a random string used to prevent replay attacks.
	Nonce *string `json:"nonce,omitempty"`
	// Rights are the rights of the user.
	Rights []string `json:"rights,omitempty"`
	// SessionID is the session ID of the external provider.
	SessionID string `json:"session_id"`
	// Token is the SAML or JWT token of the external provider.
	Token string `json:"token"`
	// System configuration client_id value.
	ClientID string `json:"client_id"`
	// ProviderID is the ID of the external provider.
	ProviderID string `json:"provider_id"`
	// TOS indicates whether the user has accepted the terms of service.
	TOS bool `json:"tos"`
	// Organizations contains organizations of the authorized user and granted roles in the organization.
	Organizations []*AuthUserOrganization `json:"organizations,omitempty"`
	// RawClaims contains all claims from the external provider.
	RawClaims map[string]any `json:"raw_claims,omitempty"`
}
