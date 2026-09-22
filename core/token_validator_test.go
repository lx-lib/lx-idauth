package core

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lx-lib/lx-idauth/core/auth"
	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
)

type stubClientStore struct {
	validateFn func(*ClientCredentials) error
}

func (s *stubClientStore) RefetchClients() error {
	return nil
}

func (s *stubClientStore) GetClient(clientID string) (*Client, error) {
	return nil, nil
}

func (s *stubClientStore) GetClients() []Client {
	return nil
}

func (s *stubClientStore) ValidateCredentials(credentials *ClientCredentials) error {
	if s.validateFn != nil {
		return s.validateFn(credentials)
	}

	return nil
}

func TestNewTokenValidatorReturnsIAMValidator(t *testing.T) {
	t.Parallel()

	validator, err := NewTokenValidator(GRANT_TYPE_IAM, &stubClientStore{}, nil, &IAMAuthTokenValidatorConfig{
		Issuer:  "urn:test:iam",
		JWKSURL: "https://example.com/jwks",
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if _, ok := validator.(*IAMAuthTokenValidator); !ok {
		t.Fatalf("expected IAMAuthTokenValidator, got %T", validator)
	}
}

func TestNewTokenValidatorReturnsErrorWhenIAMConfigMissing(t *testing.T) {
	t.Parallel()

	validator, err := NewTokenValidator(GRANT_TYPE_IAM, &stubClientStore{}, nil, nil)
	if err == nil {
		t.Fatal("expected error when IAM config is missing")
	}

	if validator != nil {
		t.Fatalf("expected nil validator, got %T", validator)
	}

	if err.Error() != "iam token validator config is required" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewTokenValidatorReturnsErrorWhenPFASConfigMissing(t *testing.T) {
	t.Parallel()

	validator, err := NewTokenValidator(GRANT_TYPE_PFAS, &stubClientStore{}, nil, nil)
	if err == nil {
		t.Fatal("expected error when PFAS config is missing")
	}

	if validator != nil {
		t.Fatalf("expected nil validator, got %T", validator)
	}

	if err.Error() != "pfas token validator config is required" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestIAMAuthTokenValidatorValidateToken(t *testing.T) {
	t.Parallel()

	const issuer = "urn:test:iam"
	const clientID = "iam-client"

	key := mustGenerateRSAKey(t)
	server := newTestJWKSServer(t, key, "test-key")
	defer server.Close()

	store := &stubClientStore{
		validateFn: func(credentials *ClientCredentials) error {
			if credentials.ClientID != clientID {
				t.Fatalf("expected client ID %q, got %q", clientID, credentials.ClientID)
			}

			if credentials.ClientSecret != nil {
				t.Fatalf("expected no client secret for IAM grant")
			}

			if credentials.Scope != nil {
				t.Fatalf("expected no scope validation for IAM grant")
			}

			if credentials.GrantType != GRANT_TYPE_IAM {
				t.Fatalf("expected IAM grant type, got %q", credentials.GrantType)
			}

			return nil
		},
	}

	validator := NewIAMAuthTokenValidator(store, &IAMAuthTokenValidatorConfig{
		Issuer:  issuer,
		JWKSURL: server.URL,
	})

	rawToken := signIAMToken(t, key, "test-key", issuer, clientID, time.Now().UTC())
	result, err := validateIAMToken(t, validator, rawToken)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if !result.Valid {
		t.Fatal("expected validated IAM token to be marked valid")
	}

	if result.ClientID != clientID {
		t.Fatalf("expected result client ID %q, got %q", clientID, result.ClientID)
	}
}

func TestIAMAuthTokenValidatorRejectsInvalidSignature(t *testing.T) {
	t.Parallel()

	const issuer = "urn:test:iam"

	jwksKey := mustGenerateRSAKey(t)
	signingKey := mustGenerateRSAKey(t)
	server := newTestJWKSServer(t, jwksKey, "test-key")
	defer server.Close()

	validator := NewIAMAuthTokenValidator(&stubClientStore{}, &IAMAuthTokenValidatorConfig{
		Issuer:  issuer,
		JWKSURL: server.URL,
	})

	rawToken := signIAMToken(t, signingKey, "other-key", issuer, "iam-client", time.Now().UTC())
	_, err := validateIAMToken(t, validator, rawToken)
	assertAuthorizeError(t, err, auth.AuthErrInvalidToken)
}

func TestIAMAuthTokenValidatorRejectsIssuerMismatch(t *testing.T) {
	t.Parallel()

	key := mustGenerateRSAKey(t)
	server := newTestJWKSServer(t, key, "test-key")
	defer server.Close()

	validator := NewIAMAuthTokenValidator(&stubClientStore{}, &IAMAuthTokenValidatorConfig{
		Issuer:  "urn:test:iam",
		JWKSURL: server.URL,
	})

	rawToken := signIAMToken(t, key, "test-key", "urn:test:other-issuer", "iam-client", time.Now().UTC())
	_, err := validateIAMToken(t, validator, rawToken)
	assertAuthorizeError(t, err, auth.AuthErrInvalidToken)
}

func TestIAMAuthTokenValidatorRejectsMissingClientID(t *testing.T) {
	t.Parallel()

	const issuer = "urn:test:iam"

	key := mustGenerateRSAKey(t)
	server := newTestJWKSServer(t, key, "test-key")
	defer server.Close()

	validator := NewIAMAuthTokenValidator(&stubClientStore{}, &IAMAuthTokenValidatorConfig{
		Issuer:  issuer,
		JWKSURL: server.URL,
	})

	rawToken := signIAMToken(t, key, "test-key", issuer, "", time.Now().UTC())
	_, err := validateIAMToken(t, validator, rawToken)
	assertAuthorizeError(t, err, auth.AuthErrInvalidToken)
}

func TestIAMAuthTokenValidatorRejectsFutureNotBefore(t *testing.T) {
	t.Parallel()

	const issuer = "urn:test:iam"

	key := mustGenerateRSAKey(t)
	server := newTestJWKSServer(t, key, "test-key")
	defer server.Close()

	validator := NewIAMAuthTokenValidator(&stubClientStore{}, &IAMAuthTokenValidatorConfig{
		Issuer:  issuer,
		JWKSURL: server.URL,
	})

	rawToken := signIAMToken(t, key, "test-key", issuer, "iam-client", time.Now().UTC().Add(5*time.Minute))
	_, err := validateIAMToken(t, validator, rawToken)
	assertAuthorizeError(t, err, auth.AuthErrInvalidToken)
}

func TestCompositeClientStoreValidateCredentialsSkipsSecretForServiceTokenGrants(t *testing.T) {
	t.Parallel()

	for _, grantType := range []string{GRANT_TYPE_PFAS, GRANT_TYPE_IAM} {
		store := &CompositeClientStore{
			clients: map[string]Client{
				"service-client": {
					ID:              "service-client",
					GrantTypes:      []string{grantType},
					isServiceClient: true,
				},
			},
		}

		err := store.ValidateCredentials(&ClientCredentials{
			ClientID:     "service-client",
			ClientSecret: nil,
			GrantType:    grantType,
		})
		if err != nil {
			t.Fatalf("expected %q grant to skip client secret validation, got %v", grantType, err)
		}
	}
}

func mustGenerateRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	return key
}

func newTestJWKSServer(t *testing.T, key *rsa.PrivateKey, keyID string) *httptest.Server {
	t.Helper()

	keySet := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{{
			Key:       &key.PublicKey,
			KeyID:     keyID,
			Use:       "sig",
			Algorithm: string(jose.RS256),
		}},
	}

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(keySet); err != nil {
			t.Errorf("failed to encode JWKS response: %v", err)
		}
	}))
}

func signIAMToken(t *testing.T, key *rsa.PrivateKey, keyID string, issuer string, clientID string, notBefore time.Time) string {
	t.Helper()

	signer, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: jose.RS256,
			Key: jose.JSONWebKey{
				Key:       key,
				KeyID:     keyID,
				Use:       "sig",
				Algorithm: string(jose.RS256),
			},
		},
		(&jose.SignerOptions{}).
			WithType("at+jwt").
			WithHeader("kid", keyID),
	)
	if err != nil {
		t.Fatalf("failed to create JWT signer: %v", err)
	}

	now := time.Now().UTC()
	token, err := josejwt.Signed(signer).Claims(josejwt.Claims{
		Issuer:    issuer,
		Subject:   "subject",
		Audience:  josejwt.Audience{"urn:test:resource"},
		Expiry:    josejwt.NewNumericDate(now.Add(time.Hour)),
		IssuedAt:  josejwt.NewNumericDate(now),
		NotBefore: josejwt.NewNumericDate(notBefore),
	}).Claims(struct {
		ClientID string `json:"client_id,omitempty"`
	}{
		ClientID: clientID,
	}).Serialize()
	if err != nil {
		t.Fatalf("failed to sign IAM token: %v", err)
	}

	return token
}

func validateIAMToken(t *testing.T, validator *IAMAuthTokenValidator, rawToken string) (*TokenValidationResult, error) {
	t.Helper()
	return validator.validateToken(context.Background(), rawToken)
}

func assertAuthorizeError(t *testing.T, err error, code auth.AuthErrCode) {
	t.Helper()

	if err == nil {
		t.Fatal("expected authorize error, got nil")
	}

	authErr, ok := err.(*auth.AuthorizeError)
	if !ok {
		t.Fatalf("expected AuthorizeError, got %T", err)
	}

	if authErr.Code != code {
		t.Fatalf("expected authorize error code %q, got %q", code, authErr.Code)
	}
}
