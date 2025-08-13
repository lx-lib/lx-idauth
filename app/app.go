package app

import (
	"errors"

	"github.com/nobid-lsp-latvia/lx-idauth"
	"github.com/nobid-lsp-latvia/lx-idauth/core"

	"azugo.io/azugo"
	"azugo.io/azugo/config"
	"azugo.io/azugo/server"
	"azugo.io/opentelemetry"
	"github.com/spf13/cobra"
)

// App is the application instance.
type App struct {
	*azugo.App

	auth   *idauth.IDAuth
	config *Configuration
}

// New returns a new application instance.
func New(cmd *cobra.Command, version string) (*App, error) {
	config := &Configuration{
		Configuration: config.New(),
	}

	app, err := server.New(cmd, server.Options{
		AppName:       "IDAuth",
		AppVer:        version,
		Configuration: config,
	})
	if err != nil {
		return nil, err
	}

	app.RouterOptions().CORS.SetHeaders("Accept", "Content-Type", "Authorization")

	clientStore, err := core.NewCompositeClientStore(app, core.CompositeClientStoreConfig{
		ClientPath: config.ClientStoreFile,
		APIUrl:     config.ClientStoreAPIURL,
		APIKey:     config.ClientStoreAPIKey,
	})
	if err != nil {
		return nil, err
	}

	var authProviderStore core.AuthProviderStore
	if config.AuthProviderStoreType == "file" {
		authProviderStore, err = core.NewFileAuthProviderStore(app, core.AuthProviderStoreFileConfig{
			Path: config.AuthProviderStoreFile,
		})
		if err != nil {
			return nil, err
		}
	}

	ootStore, err := NewAzugoCacheOOTStore(app)
	if err != nil {
		return nil, err
	}

	corelationStore, err := NewAzugoCacheCorrelationStore(app)
	if err != nil {
		return nil, err
	}

	sessionStore, err := idauth.NewAzugoCacheSessionStore(app)
	if err != nil {
		return nil, err
	}

	var authorizer core.Authorizer

	switch config.AuthorizerType {
	case "rest_api":
		authorizer = core.NewRestApiAuthorizer(&core.RestApiAuthorizerConfig{
			EndpointUrl: config.AuthorizerRestAPIURL,
			ApiKey:      config.AuthorizerRestAPIKey,
		})
	case "noop":
		authorizer = core.NewNoopAuthorizer()
	default:
		return nil, errors.New("unsupported authorizer type. valid values are rest_api, noop")
	}

	var auditProvider core.AuditProvider

	switch config.AuditType {
	case "noop":
		auditProvider = core.NewNoopAuditProvider()
	case "rest_api":
		auditProvider, err = core.NewRestAPIAuditProvider(&core.RestAPIAuditProviderConfig{
			AuditUrl:               config.AuditRestAPIUrl,
			AuditIncludePersonData: config.AuditIncludePersonData,
			AuditRestAPIKey:        config.AuditRestAPIKey,
		})
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("unsupported audit provider. valid values noop, rest_api")
	}

	auth := idauth.New(app).
		WithConfig(config).
		WithClientStore(clientStore).
		WithAuthProviderStore(authProviderStore).
		WithCorrelationStore(corelationStore).
		WithOOTStore(ootStore).
		WithSessionStore(sessionStore).
		WithAuthorizer(authorizer).
		WithAuditProvider(auditProvider)

	a := &App{
		App:    app,
		auth:   auth,
		config: config,
	}

	tel, err := opentelemetry.Use(app, config.Telemetry)
	if err != nil {
		return nil, err
	}

	if err := a.AddTask(tel); err != nil {
		return nil, err
	}

	return a, nil
}

// Config returns application configuration.
//
// Panics if configuration is not loaded.
func (a *App) Config() *Configuration {
	if a.config == nil || !a.config.Ready() {
		panic("configuration is not loaded")
	}

	return a.config
}

// Correlation store.
func (a *App) Correlation() core.CorrelationStore {
	if a.config == nil || !a.config.Ready() {
		panic("configuration is not loaded")
	}

	return a.auth.Correlation()
}

// Start the application.
func (a *App) Start() error {
	return a.App.Start()
}

// Stop the application.
func (a *App) Stop() {
	a.App.Stop()
}

func (a *App) Auth() *idauth.IDAuth {
	return a.auth
}
