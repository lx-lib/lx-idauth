package core

type Client struct {
	ID              string            `json:"client_id,omitempty" yaml:"client_id,omitempty" validate:"required"`
	RedirectURI     []string          `json:"redirect_uri,omitempty" yaml:"redirect_uri,omitempty"`
	GrantTypes      []string          `json:"grant_types,omitempty" yaml:"grant_types,omitempty"`
	Scopes          []string          `json:"scopes,omitempty" yaml:"scopes,omitempty"`
	Metadata        map[string]string `json:"metadata,omitempty" yaml:"metadata,omitempty"`
	Secrets         []string          `json:"client_secret,omitempty" yaml:"client_secret,omitempty"`
	Certificates    []string          `json:"client_certificate,omitempty" yaml:"client_certificate,omitempty"`
	Claims          map[string]any    `json:"claims,omitempty" yaml:"claims,omitempty"`
	isServiceClient bool
}

type ClientCredentials struct {
	ClientID     string
	ClientSecret *string
	Scope        *string
	GrantType    string
}

type ClientStore interface {
	RefetchClients() error
	GetClient(clientID string) (*Client, error)
	GetClients() []Client
	ValidateCredentials(credentials *ClientCredentials) error
}
