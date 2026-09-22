package app

import (
	"errors"
	"strings"
	"time"

	idauth "github.com/lx-lib/lx-idauth"

	"azugo.io/azugo/config"
	loader "azugo.io/core/config"
	"azugo.io/core/validation"
	"azugo.io/opentelemetry"
	jsondb "github.com/lx-lib/lx-go-jsondb"
	"github.com/spf13/viper"
)

// Configuration represents the configuration for the application.
type Configuration struct {
	*config.Configuration `mapstructure:",squash"`
	Telemetry             *opentelemetry.Configuration `mapstructure:"telemetry" validate:"omitempty"`

	Postgres                   *jsondb.Configuration `mapstructure:"postgres"`
	SessionStoreType           string                `mapstructure:"session_store_type"`
	EnableSessionStoreCleanup  bool                  `mapstructure:"enable_session_store_cleanup"`
	CleanupCronExpression      string                `mapstructure:"cleanup_cron_expression"`
	SessionTimeout             time.Duration         `mapstructure:"session_timeout" validate:"gt=0,omitempty"`
	SessionCountdown           time.Duration         `mapstructure:"session_countdown"`
	IntrospectionURL           string                `mapstructure:"introspection_url"`
	IntrospectionClientID      string                `mapstructure:"introspection_client_id"`
	IntrospectionClientSecret  string                `mapstructure:"introspection_client_secret"`
	IAMIssuer                  string                `mapstructure:"iam_issuer" validate:"omitempty"`
	IAMJWKSURL                 string                `mapstructure:"iam_jwks_url" validate:"omitempty,url"`
	ClientStoreFile            string                `mapstructure:"client_store_file" validate:"omitempty"`
	ClientStoreAPIURL          string                `mapstructure:"client_store_api_url" validate:"omitempty"`
	ClientStoreAPIKey          string                `mapstructure:"client_store_api_key" validate:"omitempty"`
	AuthProviderStoreType      string                `mapstructure:"auth_provider_store_type" validate:"omitempty"`
	AuthProviderStoreFile      string                `mapstructure:"auth_provider_store_file" validate:"omitempty"`
	AuthorizerType             string                `mapstructure:"authorizer_type" validate:"omitempty"`
	AuthorizerRestAPIURL       string                `mapstructure:"authorizer_rest_api_url" validate:"omitempty"`
	AuthorizerRestAPIKey       string                `mapstructure:"authorizer_rest_api_key" validate:"omitempty"`
	AuthorizerRequiresTOS      bool                  `mapstructure:"authorizer_requires_tos" validate:"omitempty"`
	TOSEndpoint                string                `mapstructure:"tos_endpoint" validate:"omitempty"`
	AuditType                  string                `mapstructure:"audit_type" validate:"omitempty"`
	AuditRestAPIUrl            string                `mapstructure:"audit_url" validate:"omitempty"`
	AuditIncludePersonData     bool                  `mapstructure:"audit_include_person_data" validate:"omitempty"`
	AuditRestAPIKey            string                `mapstructure:"audit_rest_api_key" validate:"omitempty"`
	SessionRequiresRole        bool                  `mapstructure:"session_requires_role" validate:"omitempty"`
	UsesAuthorizationCodeGrant bool                  `mapstructure:"uses_authorization_code_grant" validate:"omitempty"`
	UsesIAMGrant               bool                  `mapstructure:"uses_iam_grant" validate:"omitempty"`
	UsesPfasGrant              bool                  `mapstructure:"uses_pfas_grant" validate:"omitempty"`
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
	c.Postgres = config.Bind(c.Postgres, "postgres", v)

	apiKey, _ := loader.LoadRemoteSecret("AUTHORIZER_REST_API_KEY")
	clientStoreAPIKey, _ := loader.LoadRemoteSecret("CLIENT_STORE_API_KEY")
	auditKey, _ := loader.LoadRemoteSecret("AUDIT_API_KEY")
	introspectionClientID, _ := loader.LoadRemoteSecret("INTROSPECTION_CLIENT_ID")
	introspectionClientSecret, _ := loader.LoadRemoteSecret("INTROSPECTION_CLIENT_SECRET")

	v.SetDefault("session_store_type", "cache")
	v.SetDefault("session_store_cleanup_enabled", true)
	v.SetDefault("session_store_cleanup_cron", "0 4 * * *")
	v.SetDefault("session_timeout", "60m")
	v.SetDefault("session_countdown", "5m")
	v.SetDefault("client_store_file", ".config/clients.yaml")
	v.SetDefault("auth_provider_store_type", "file")
	v.SetDefault("auth_provider_store_file", ".config/providers.yaml")
	v.SetDefault("authorizer_type", "rest_api")
	v.SetDefault("authorizer_rest_api_key", apiKey)
	v.SetDefault("authorizer_requires_tos", false)
	v.SetDefault("audit_type", "noop")
	v.SetDefault("audit_include_person_data", false)
	v.SetDefault("audit_rest_api_key", auditKey)
	v.SetDefault("client_store_api_key", clientStoreAPIKey)
	v.SetDefault("introspection_client_id", introspectionClientID)
	v.SetDefault("introspection_client_secret", introspectionClientSecret)
	v.SetDefault("uses_authorization_code_grant", false)
	v.SetDefault("uses_iam_grant", false)
	v.SetDefault("uses_pfas_grant", true)
	v.SetDefault("session_requires_role", false)

	_ = v.BindEnv("session_store_type", "SESSION_STORE_TYPE")
	_ = v.BindEnv("enable_session_store_cleanup", "ENABLE_SESSION_STORE_CLEANUP")
	_ = v.BindEnv("cleanup_cron_expression", "CLEANUP_CRON_EXPRESSION")
	_ = v.BindEnv("session_timeout", "SESSION_TIMEOUT")
	_ = v.BindEnv("session_countdown", "SESSION_COUNTDOWN")
	_ = v.BindEnv("introspection_url", "INTROSPECTION_URL")
	_ = v.BindEnv("introspection_client_id", "INTROSPECTION_CLIENT_ID")
	_ = v.BindEnv("introspection_client_secret", "INTROSPECTION_CLIENT_SECRET")
	_ = v.BindEnv("iam_issuer", "IAM_ISSUER")
	_ = v.BindEnv("iam_jwks_url", "IAM_JWKS_URL")
	_ = v.BindEnv("client_store_file", "CLIENT_STORE_FILE")
	_ = v.BindEnv("client_store_api_url", "CLIENT_STORE_API_URL")
	_ = v.BindEnv("client_store_api_key", "CLIENT_STORE_API_KEY")
	_ = v.BindEnv("auth_provider_store_type", "AUTH_PROVIDER_STORE_TYPE")
	_ = v.BindEnv("auth_provider_store_file", "AUTH_PROVIDER_STORE_FILE")
	_ = v.BindEnv("authorizer_type", "AUTHORIZER_TYPE")
	_ = v.BindEnv("authorizer_rest_api_url", "AUTHORIZER_REST_API_URL")
	_ = v.BindEnv("authorizer_rest_api_key", "AUTHORIZER_REST_API_KEY")
	_ = v.BindEnv("authorizer_requires_tos", "AUTHORIZER_REQUIRES_TOS")
	_ = v.BindEnv("tos_endpoint", "TOS_ENDPOINT")
	_ = v.BindEnv("audit_type", "AUDIT_TYPE")
	_ = v.BindEnv("audit_url", "AUDIT_URL")
	_ = v.BindEnv("audit_include_person_data", "AUDIT_INCLUDE_PERSON_DATA")
	_ = v.BindEnv("audit_rest_api_key", "AUDIT_API_KEY")
	_ = v.BindEnv("uses_authorization_code_grant", "USES_AUTHORIZATION_CODE_GRANT")
	_ = v.BindEnv("uses_iam_grant", "USES_IAM_GRANT")
	_ = v.BindEnv("uses_pfas_grant", "USES_PFAS_GRANT")
	_ = v.BindEnv("session_requires_role", "SESSION_REQUIRES_ROLE")
}

// Validate application configuration.
func (c *Configuration) Validate(validate *validation.Validate) error {
	if err := c.Telemetry.Validate(validate); err != nil {
		return err
	}

	if c.SessionStoreType == "postgres" {
		if err := validate.Struct(c.Postgres); err != nil {
			return err
		}
	}

	if err := validate.StructExcept(c, "Postgres"); err != nil {
		return err
	}

	if c.UsesIAMGrant {
		if strings.TrimSpace(c.IAMIssuer) == "" {
			return errors.New("iam_issuer is required when uses_iam_grant is enabled")
		}

		if strings.TrimSpace(c.IAMJWKSURL) == "" {
			return errors.New("iam_jwks_url is required when uses_iam_grant is enabled")
		}
	}

	return nil
}

func (c *Configuration) ExposedConfig() *idauth.Configuration {
	return &idauth.Configuration{
		IntrospectionURL:           c.IntrospectionURL,
		IntrospectionClientID:      c.IntrospectionClientID,
		IntrospectionClientSecret:  c.IntrospectionClientSecret,
		IAMIssuer:                  c.IAMIssuer,
		IAMJWKSURL:                 c.IAMJWKSURL,
		SessionTimeout:             c.SessionTimeout,
		SessionCountdown:           c.SessionCountdown,
		AuthorizerRestAPIKey:       c.AuthorizerRestAPIKey,
		AuthorizerRequiresTOS:      c.AuthorizerRequiresTOS,
		TOSEndpoint:                c.TOSEndpoint,
		SessionRequiresRole:        c.SessionRequiresRole,
		UsesAuthorizationCodeGrant: c.UsesAuthorizationCodeGrant,
		UsesIAMGrant:               c.UsesIAMGrant,
		UsesPfasGrant:              c.UsesPfasGrant,
		Postgres:                   c.Postgres,
	}
}
