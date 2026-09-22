package core

import (
	"time"

	"azugo.io/azugo"
)

// Correlation represents a authorization request correlation.
type Correlation struct {
	// ID is a unique identifier of the session
	ID string `json:"id"`
	// ClientID is a unique identifier of the client
	ClientID string `json:"client_id"`
	// RedirectURI is a URI that the client will be redirected to after authorization
	RedirectURI string `json:"redirect_uri"`
	// Nonce is a unique identifier of the authorization request
	Nonce *string `json:"nonce"`
	// State is a unique identifier of the authorization request
	State *string `json:"state"`
	// CodeChallenge is a unique identifier of the authorization request
	CodeChallenge *string `json:"code_challenge"`
	// CodeChallenge is a unique identifier of the authorization request
	CodeChallengeMethod *string `json:"code_challenge_method"`
	// ErrorCode is an error code that occurred during authorization
	ErrorCode string `json:"error_code"`
	// ManagedByProvider is a flag that indicates if the session is managed by the provider
	ManagedByProvider bool `json:"managed_by_provider"`
	// SessionCreated is a time when the session was created if the session is not managed by the provider
	SessionCreated *time.Time `json:"session_created"`
	// TOSTargetURI is the computed TOS redirect URI, used for redirecting to TOS page if required
	TOSTargetURI *string `json:"tos_target_uri,omitempty"`
}

type CorrelationStore interface {
	Set(ctx *azugo.Context, correlation *Correlation) (*Correlation, error)
	Get(ctx *azugo.Context) (*Correlation, error)
	Delete(ctx *azugo.Context) error
}

type OneTimeToken struct {
	ID             string     `json:"id"`
	RedirectURI    string     `json:"redirect_uri"`
	RedirectURIs   []string   `json:"redirect_uris,omitempty"` // alternative valid redirect uri's
	SessionToken   string     `json:"session_token"`
	SessionCreated *time.Time `json:"session_created"`
}

// OTTStore manages the generation and exchange of one-time tokens.
type OTTStore interface {
	GenerateToken(ctx *azugo.Context, session *Correlation) (*OneTimeToken, error)
	GetToken(ctx *azugo.Context, token string) (*OneTimeToken, error)
	RedeemToken(ctx *azugo.Context, token string) (*OneTimeToken, error)
}
