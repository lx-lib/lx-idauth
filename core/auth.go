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
	PostCallbackSignout   bool              `yaml:"post_callback_signout" json:"postCallbackSignout"`                                 // For WSFED
	ClientID              string            `yaml:"client_id" json:"client_id,omitempty"`                                             // For OpenID
	ClientSecret          string            `yaml:"client_secret" json:"client_secret,omitempty"`                                     // For OpenID
	Metadata              map[string]string `yaml:"metadata" json:"metadata,omitempty"`
	Scope                 []string          `yaml:"scope" json:"scope,omitempty"`
	AcrValues             string            `yaml:"acr_values" json:"acr_values,omitempty"`
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

type AuthRequest struct {
	// PersonCode is the person code of the authorized user.
	PersonCode string
	// FirstName is the first name of the authorized user.
	FirstName string
	// LastName is the last name of the authorized user.
	LastName string
	Email    string
	// LegalCode is the legal code of institution user represents.
	LegalCode string
	// LegalName is the legal name of institution user represents.
	LegalName string
	// IPAddress is the IP address of the user.
	IPAddress string
	// Nonce is a random string used to prevent replay attacks.
	Nonce *string
	// Rights is the rights of the user.
	Rights []string
	// SessionID is the session ID of the external provider.
	SessionID string
	// Token is the SAML or JWT token of the external provider.
	Token string
	// System configuration client_id value.
	ClientID string
}
