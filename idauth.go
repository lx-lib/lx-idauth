package idauth

import (
	"errors"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/nobid-lsp-latvia/lx-idauth/core"
	"github.com/nobid-lsp-latvia/lx-idauth/core/auth"

	"azugo.io/azugo"
	"azugo.io/azugo/user"
	"github.com/valyala/fasthttp"
	"go.uber.org/zap"
)

type Configuration struct {
	IntrospectionURL           string
	IntrospectionClientID      string
	IntrospectionClientSecret  string
	SessionTimeout             time.Duration
	SessionCountdown           time.Duration
	AuthorizerRestAPIKey       string
	SessionRequiresRole        bool
	UsesAuthorizationCodeGrant bool
}

type IDAuthConfig interface {
	ExposedConfig() *Configuration
}

// IDAuth service.
type IDAuth struct {
	config            IDAuthConfig
	app               *azugo.App
	clientStore       core.ClientStore
	authProviderStore core.AuthProviderStore
	correlationStore  core.CorrelationStore
	sessionStore      core.SessionStore
	ootStore          core.OTTStore
	authorizer        core.Authorizer
	auditProvider     core.AuditProvider
	authProvidersMu   sync.RWMutex
	authProviders     map[string]core.AuthProvider
}

// New creates a new IDAuth instance.
func New(app *azugo.App) *IDAuth {
	return &IDAuth{
		app:           app,
		authProviders: make(map[string]core.AuthProvider),
	}
}

func (a *IDAuth) Init() error {
	providers, err := a.authProviderStore.GetAllProviders()
	if err != nil {
		return err
	}

	for _, provider := range providers {
		switch strings.ToLower(provider.Type) {
		case "vpm":
			vpm, err := NewVPMService(a, provider)
			if err != nil {
				return err
			}
			a.Register(provider.ID, vpm)
		case "oidc":
			oidc, err := NewOidcService(a, provider)
			if err != nil {
				return err
			}
			a.Register(provider.ID, oidc)
		default:
			return errors.New("auth type not supported")
		}

		a.app.Log().Info("Auth provider registered",
			zap.String("id", provider.ID),
			zap.String("type", provider.Type),
		)
	}

	return nil
}

func (a *IDAuth) WithClientStore(s core.ClientStore) *IDAuth {
	a.clientStore = s
	return a
}

func (a *IDAuth) WithAuthProviderStore(s core.AuthProviderStore) *IDAuth {
	a.authProviderStore = s
	return a
}

func (a *IDAuth) WithCorrelationStore(s core.CorrelationStore) *IDAuth {
	a.correlationStore = s
	return a
}

func (a *IDAuth) WithSessionStore(s core.SessionStore) *IDAuth {
	a.sessionStore = s
	return a
}

func (a *IDAuth) WithOOTStore(s core.OTTStore) *IDAuth {
	a.ootStore = s
	return a
}

func (a *IDAuth) WithAuthorizer(s core.Authorizer) *IDAuth {
	a.authorizer = s
	return a
}

func (a *IDAuth) WithAuditProvider(s core.AuditProvider) *IDAuth {
	a.auditProvider = s
	return a
}

func (a *IDAuth) WithConfig(c IDAuthConfig) *IDAuth {
	a.config = c
	return a
}

// Correlation store.
func (a *IDAuth) Correlation() core.CorrelationStore {
	return a.correlationStore
}

// Session store.
func (a *IDAuth) Session() core.SessionStore {
	return a.sessionStore
}

// Authorizier service.
func (a *IDAuth) Authorizer() core.Authorizer {
	return a.authorizer
}

// Clients store.
func (a *IDAuth) Clients() core.ClientStore {
	return a.clientStore
}

// OTT store.
func (a *IDAuth) OTT() core.OTTStore {
	return a.ootStore
}

// Bind IDAuth endpoints.
func (a *IDAuth) Bind(r azugo.Router) {
	// Metadata endpoint.
	r.Get("/.well-known/oauth-authorization-server", a.metadata())

	r.Post("/token", a.token)
	r.Get("/authorize", a.authorize)
	r.Get("/callback/{id}", a.callback)
	r.Post("/callback/{id}", a.callback)

	webhooks := r.Group("/webhooks")
	webhooks.Use(AuthorizeStaticToken(a))
	webhooks.Post("/clients/reload", a.clientsReload)

	r.Use(AuthorizeBearer(a))
	r = r.Group("/api/1.0")
	r.Get("/session", a.getSession)
	r.Get("/session/keep-alive", a.extendSession)
	r.Get("/session/roles", a.getSessionAvailableRoles)
	r.Patch("/session", a.setSessionRole)
	r.Delete("/session", a.deleteSession)
	r.Get("/config", a.getConfigValues)
}

// RedirectToCaller redirects to the client with the code.
func (a *IDAuth) RedirectToCaller(ctx *azugo.Context, sess *core.Correlation) error {
	returnURL, err := url.Parse(sess.RedirectURI)
	if err != nil {
		a.app.Log().Error("parsing redirect URI", zap.Error(err))
		return err
	}
	q := returnURL.Query()
	if sess.State != nil {
		q.Set("state", *sess.State)
	}
	if len(sess.ErrorCode) > 0 {
		q.Set("error", sess.ErrorCode)
	} else {
		if a.config.ExposedConfig().UsesAuthorizationCodeGrant && !sess.ManagedByProvider {
			ott, err := a.ootStore.GenerateToken(ctx, sess)
			if err != nil {
				return err
			}
			q.Set("code", ott.ID)
		} else {
			q.Set("code", sess.ID)
		}
	}
	returnURL.RawQuery = q.Encode()

	_ = a.correlationStore.Delete(ctx)

	ctx.Redirect(returnURL.String())
	return nil
}

// AuthorizeBearer returns a middleware that authenticates the user based on provided AuthorizeBearer header.
func AuthorizeBearer(a *IDAuth) func(azugo.RequestHandler) azugo.RequestHandler {
	return func(h azugo.RequestHandler) azugo.RequestHandler {
		return func(ctx *azugo.Context) {
			if ctx.Method() == fasthttp.MethodOptions {
				h(ctx)
				return
			}
			token := ctx.Header.Get("Authorization")
			if len(token) == 0 || strings.ToLower(token) == "bearer null" || !strings.HasPrefix(strings.ToLower(token), AuthorizationBearer) {
				ctx.StatusCode(fasthttp.StatusUnauthorized)
				return
			}

			session, err := a.sessionStore.GetSessionByID(ctx, strings.TrimSpace(token[len(AuthorizationBearer):]))
			if err != nil {
				if errors.As(err, &ErrSessionNotFoundError{}) {
					ctx.StatusCode(fasthttp.StatusUnauthorized)
					ctx.JSON(&auth.AuthorizeError{
						Code:    auth.AuthErrNoSession,
						Message: "Session not found",
					})
					return
				}

				a.app.Log().Error("getting user session", zap.Error(err))
				ctx.Error(err)
				return
			}

			ctx.SetUserValue(SessionUserValueKey, session)
			ctx.SetUser(user.New(session.ToClaims()))
			h(ctx)
		}
	}
}

func AuthorizeStaticToken(a *IDAuth) func(azugo.RequestHandler) azugo.RequestHandler {
	return func(h azugo.RequestHandler) azugo.RequestHandler {
		return func(ctx *azugo.Context) {
			token := ctx.Header.Get("X-API-KEY")
			if len(token) == 0 || token != a.config.ExposedConfig().AuthorizerRestAPIKey {
				ctx.StatusCode(fasthttp.StatusUnauthorized)
				return
			}

			h(ctx)
		}
	}
}
