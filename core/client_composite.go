package core

import (
	"context"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"slices"
	"strings"

	"github.com/lx-lib/lx-idauth/core/auth"

	"azugo.io/azugo"
	"azugo.io/core/validation"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

type clientSource interface {
	LoadClients() ([]Client, error)
}

type fileSource struct {
	path           string
	serviceClients bool
}

type apiSource struct {
	url            string
	apiKey         string
	serviceClients bool
}

type CompositeClientStore struct {
	app     *azugo.App
	sources []clientSource
	clients map[string]Client
}

type CompositeClientStoreConfig struct {
	ClientPath string `mapstructure:"client_path" validate:"required"`
	APIUrl     string `mapstructure:"api_url"`
	APIKey     string `mapstructure:"api_key"`
}

func NewCompositeClientStore(app *azugo.App, config CompositeClientStoreConfig) (*CompositeClientStore, error) {
	if config.ClientPath == "" {
		return nil, errors.New("client file store path is required")
	}

	store := &CompositeClientStore{
		app:     app,
		clients: make(map[string]Client),
	}

	store.sources = append(store.sources, &fileSource{
		path:           config.ClientPath,
		serviceClients: false,
	})

	if config.APIUrl != "" {
		store.sources = append(store.sources, &apiSource{
			url:            config.APIUrl,
			apiKey:         config.APIKey,
			serviceClients: true,
		})
	}

	if err := store.loadClients(); err != nil {
		return nil, err
	}

	return store, nil
}

func (s *CompositeClientStore) loadClients() error {
	validator := validation.New()
	newClients := make(map[string]Client)

	for _, source := range s.sources {
		clients, err := source.LoadClients()
		if err != nil {
			return err
		}

		for _, client := range clients {
			if err := validator.Struct(client); err != nil {
				return err
			}

			if _, ok := newClients[client.ID]; ok {
				s.app.Log().Error("Duplicate client ID", zap.String("client_id", client.ID))
				continue
			}

			newClients[client.ID] = client
		}
	}

	s.clients = newClients
	return nil
}

func (s *CompositeClientStore) RefetchClients() error {
	// reloads clients from all sources
	// theoretically only API sources should be re-fetched but
	// the stored clients have no indication of where they came from
	// so a blank slate is needed regardless
	return s.loadClients()
}

func (s *CompositeClientStore) GetClient(clientID string) (*Client, error) {
	client, ok := s.clients[clientID]
	if !ok {
		return nil, &auth.AuthorizeError{
			Code:    auth.AuthErrInvalidClient,
			Message: "Client not found",
		}
	}

	return &client, nil
}

func (s *CompositeClientStore) GetClients() []Client {
	clients := make([]Client, 0, len(s.clients))
	for _, client := range s.clients {
		clients = append(clients, client)
	}

	return clients
}

func (s *CompositeClientStore) ValidateCredentials(credentials *ClientCredentials) error {
	client, err := s.GetClient(credentials.ClientID)
	if err != nil {
		return err
	}

	if !client.isServiceClient {
		return &auth.AuthorizeError{
			Code:    auth.AuthErrInvalidClient,
			Message: "Client not allowed",
		}
	}

	// Fallback for clients that still have "basic" grant type instead of "client_credentials"
	if slices.Contains(client.GrantTypes, GRANT_TYPE_BASIC) && !slices.Contains(client.GrantTypes, GRANT_TYPE_CLIENT_CREDENTIALS) {
		client.GrantTypes = append(client.GrantTypes, GRANT_TYPE_CLIENT_CREDENTIALS)
	}

	if !slices.Contains(client.GrantTypes, credentials.GrantType) {
		return &auth.AuthorizeError{
			Code:    auth.AuthErrInvalidRequest,
			Message: "Invalid grant type",
		}
	}

	if credentials.Scope != nil {
		requestedScopes := strings.Fields(*credentials.Scope)
		for _, requestedScope := range requestedScopes {
			if !slices.Contains(client.Scopes, requestedScope) {
				return &auth.AuthorizeError{
					Code:    auth.AuthErrInvalidRequest,
					Message: "Invalid scope: " + requestedScope,
				}
			}
		}
	}

	// Service-token grants are validated by the upstream issuer and local client allowlist.
	if grantTypeSkipsClientSecret(credentials.GrantType) {
		return nil
	}

	if credentials.ClientSecret == nil {
		return &auth.AuthorizeError{
			Code:    auth.AuthErrInvalidClient,
			Message: "Invalid client secret",
		}
	}

	for _, secret := range client.Secrets {
		if subtle.ConstantTimeCompare([]byte(secret), []byte(*credentials.ClientSecret)) == 1 {
			return nil
		}
	}

	return &auth.AuthorizeError{
		Code:    auth.AuthErrInvalidClient,
		Message: "Invalid client secret",
	}
}

func grantTypeSkipsClientSecret(grantType string) bool {
	return grantType == GRANT_TYPE_PFAS || grantType == GRANT_TYPE_IAM
}

func (s *fileSource) LoadClients() ([]Client, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return nil, err
	}

	var clients []Client
	if err := yaml.Unmarshal(data, &clients); err != nil {
		return nil, err
	}

	if len(clients) > 0 {
		for i := range clients {
			clients[i].isServiceClient = len(clients[i].RedirectURI) == 0
			for j := range clients[i].Secrets {
				hash := sha512.New()
				hash.Write([]byte(clients[i].Secrets[j]))
				hashedSecret := hex.EncodeToString(hash.Sum(nil))
				clients[i].Secrets[j] = hashedSecret
			}
		}
	}

	return clients, nil
}

func (s *apiSource) LoadClients() ([]Client, error) {
	req, err := http.NewRequestWithContext(context.Background(), "GET", s.url, nil)
	if err != nil {
		return nil, err
	}

	if s.apiKey != "" {
		req.Header.Set("X-API-KEY", s.apiKey)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("failed to fetch clients from API")
	}

	var clients []Client
	if err := json.NewDecoder(resp.Body).Decode(&clients); err != nil {
		return nil, err
	}

	for i := range clients {
		clients[i].isServiceClient = s.serviceClients
	}
	// if client secrets are retrieved from the DB, they are already hashed
	return clients, nil
}
