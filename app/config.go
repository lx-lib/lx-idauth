package app

import (
	"time"

	"github.com/nobid-lsp-latvia/lx-idauth"

	"azugo.io/azugo/config"
	loader "azugo.io/core/config"
	"azugo.io/core/validation"
	"azugo.io/opentelemetry"
	"github.com/spf13/viper"
)

// Configuration represents the configuration for the application.
type Configuration struct {
	*config.Configuration `mapstructure:",squash"`
	Telemetry             *opentelemetry.Configuration `mapstructure:"telemetry" validate:"omitempty"`

	SessionTimeout             time.Duration `mapstructure:"session_timeout" validate:"gt=0,omitempty"`
	SessionCountdown           time.Duration `mapstructure:"session_countdown"`
	IntrospectionURL           string        `mapstructure:"introspection_url"`
	IntrospectionClientID      string        `mapstructure:"introspection_client_id"`
	IntrospectionClientSecret  string        `mapstructure:"introspection_client_secret"`
	ClientStoreFile            string        `mapstructure:"client_store_file" validate:"omitempty"`
	ClientStoreAPIURL          string        `mapstructure:"client_store_api_url" validate:"omitempty"`
	ClientStoreAPIKey          string        `mapstructure:"client_store_api_key" validate:"omitempty"`
	AuthProviderStoreType      string        `mapstructure:"auth_provider_store_type" validate:"omitempty"`
	AuthProviderStoreFile      string        `mapstructure:"auth_provider_store_file" validate:"omitempty"`
	AuthorizerType             string        `mapstructure:"authorizer_type" validate:"omitempty"`
	AuthorizerRestAPIURL       string        `mapstructure:"authorizer_rest_api_url" validate:"omitempty"`
	AuthorizerRestAPIKey       string        `mapstructure:"authorizer_rest_api_key" validate:"omitempty"`
	AuditType                  string        `mapstructure:"audit_type" validate:"omitempty"`
	AuditRestAPIUrl            string        `mapstructure:"audit_url" validate:"omitempty"`
	AuditIncludePersonData     bool          `mapstructure:"audit_include_person_data" validate:"omitempty"`
	AuditRestAPIKey            string        `mapstructure:"audit_rest_api_key" validate:"omitempty"`
	SessionRequiresRole        bool          `mapstructure:"session_requires_role" validate:"omitempty"`
	UsesAuthorizationCodeGrant bool          `mapstructure:"uses_authorization_code_grant" validate:"omitempty"`
}

// NewConfiguration returns a new configuration.
func NewConfiguration() *Configuration {
	return &Configuration{
		Configuration: config.New(),
	}
}

// ServerCore returns the core configuration.
func (c *Configuration) ServerCore() *config.Configuration {
	return c.Configuration
}

func (c *Configuration) Bind(_ string, v *viper.Viper) {
	c.Configuration.Bind("", v)
	c.Telemetry = config.Bind(c.Telemetry, "telemetry", v)

	apiKey, _ := loader.LoadRemoteSecret("AUTHORIZER_REST_API_KEY")
	clientStoreAPIKey, _ := loader.LoadRemoteSecret("CLIENT_STORE_API_KEY")
	auditKey, _ := loader.LoadRemoteSecret("AUDIT_API_KEY")
	introspectionClientID, _ := loader.LoadRemoteSecret("INTROSPECTION_CLIENT_ID")
	introspectionClientSecret, _ := loader.LoadRemoteSecret("INTROSPECTION_CLIENT_SECRET")

	v.SetDefault("session_timeout", "60m")
	v.SetDefault("session_countdown", "5m")
	v.SetDefault("client_store_file", ".config/clients.yaml")
	v.SetDefault("session_store_type", "memory")
	v.SetDefault("auth_provider_store_type", "file")
	v.SetDefault("auth_provider_store_file", ".config/providers.yaml")
	v.SetDefault("authorizer_type", "rest_api")
	v.SetDefault("authorizer_rest_api_key", apiKey)
	v.SetDefault("audit_type", "noop")
	v.SetDefault("audit_include_person_data", false)
	v.SetDefault("audit_rest_api_key", auditKey)
	v.SetDefault("client_store_api_key", clientStoreAPIKey)
	v.SetDefault("introspection_client_id", introspectionClientID)
	v.SetDefault("introspection_client_secret", introspectionClientSecret)
	v.SetDefault("uses_authorization_code_grant", false)
	v.SetDefault("session_requires_role", false)

	_ = v.BindEnv("session_timeout", "SESSION_TIMEOUT")
	_ = v.BindEnv("session_countdown", "SESSION_COUNTDOWN")
	_ = v.BindEnv("introspection_url", "INTROSPECTION_URL")
	_ = v.BindEnv("introspection_client_id", "INTROSPECTION_CLIENT_ID")
	_ = v.BindEnv("introspection_client_secret", "INTROSPECTION_CLIENT_SECRET")
	_ = v.BindEnv("client_store_file", "CLIENT_STORE_FILE")
	_ = v.BindEnv("client_store_api_url", "CLIENT_STORE_API_URL")
	_ = v.BindEnv("client_store_api_key", "CLIENT_STORE_API_KEY")
	_ = v.BindEnv("auth_provider_store_type", "AUTH_PROVIDER_STORE_TYPE")
	_ = v.BindEnv("auth_provider_store_file", "AUTH_PROVIDER_STORE_FILE")
	_ = v.BindEnv("authorizer_type", "AUTHORIZER_TYPE")
	_ = v.BindEnv("authorizer_rest_api_url", "AUTHORIZER_REST_API_URL")
	_ = v.BindEnv("authorizer_rest_api_key", "AUTHORIZER_REST_API_KEY")
	_ = v.BindEnv("audit_type", "AUDIT_TYPE")
	_ = v.BindEnv("audit_url", "AUDIT_URL")
	_ = v.BindEnv("audit_include_person_data", "AUDIT_INCLUDE_PERSON_DATA")
	_ = v.BindEnv("audit_rest_api_key", "AUDIT_API_KEY")
	_ = v.BindEnv("uses_authorization_code_grant", "USES_AUTHORIZATION_CODE_GRANT")
	_ = v.BindEnv("session_requires_role", "SESSION_REQUIRES_ROLE")
}

// Validate application configuration.
func (c *Configuration) Validate(validate *validation.Validate) error {
	if err := c.Telemetry.Validate(validate); err != nil {
		return err
	}
	if err := validate.Struct(c); err != nil {
		return err
	}
	return nil
}

func (c *Configuration) ExposedConfig() *idauth.Configuration {
	return &idauth.Configuration{
		IntrospectionURL:           c.IntrospectionURL,
		IntrospectionClientID:      c.IntrospectionClientID,
		IntrospectionClientSecret:  c.IntrospectionClientSecret,
		SessionTimeout:             c.SessionTimeout,
		SessionCountdown:           c.SessionCountdown,
		AuthorizerRestAPIKey:       c.AuthorizerRestAPIKey,
		SessionRequiresRole:        c.SessionRequiresRole,
		UsesAuthorizationCodeGrant: c.UsesAuthorizationCodeGrant,
	}
}
