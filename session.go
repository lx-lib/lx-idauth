package idauth

import (
	"time"

	"github.com/nobid-lsp-latvia/lx-idauth/core"

	"azugo.io/azugo"
	"azugo.io/core/cache"
	"github.com/oklog/ulid/v2"
	"github.com/valyala/fasthttp"
)

func NewAzugoCacheSessionStore(app *azugo.App) (*CacheSessionStore, error) {
	store, err := cache.Create[*core.Session](app.Cache(), "idauth-session")
	if err != nil {
		return nil, err
	}

	return &CacheSessionStore{
		store: store,
	}, nil
}

type CacheSessionStore struct {
	store cache.Instance[*core.Session]
}

func (sp *CacheSessionStore) GetSessionByID(ctx *azugo.Context, id string) (*core.Session, error) {
	session, err := sp.store.Get(ctx, id)
	if err != nil {
		return nil, err
	}

	if session == nil {
		return nil, ErrSessionNotFoundError{id}
	}

	return session, nil
}

func (sp *CacheSessionStore) Create(ctx *azugo.Context, session *core.Session) (*core.Session, error) {
	if session.ID == "" {
		session.ID = ulid.Make().String()
	}
	if err := sp.store.Set(ctx, session.ID, session); err != nil {
		return nil, err
	}
	return session, nil
}

func (sp *CacheSessionStore) Update(ctx *azugo.Context, session *core.Session) (*core.Session, error) {
	if session.ID == "" {
		return nil, ErrSessionNotFoundError{session.ID}
	}
	if err := sp.store.Set(ctx, session.ID, session); err != nil {
		return nil, err
	}
	return session, nil
}

// Keep session alive in session store and in database.
func (sp *CacheSessionStore) Extend(ctx *azugo.Context, id string) (*core.Session, error) {
	if len(id) > 26 {
		return nil, ErrSessionNotFoundError{id}
	}
	// Get session from cache or load it from store
	session, err := sp.store.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if session == nil {
		return nil, ErrSessionNotFoundError{id}
	}
	now := time.Now().UTC()
	session.LastAccessed = &now
	// Ignore session cache update error, session will be loaded automatically if not in cache
	_ = sp.store.Set(ctx, session.ID, session)
	return session, nil
}

func (sp *CacheSessionStore) Delete(ctx *azugo.Context, id string) error {
	return sp.store.Delete(ctx, id)
}

// GetSession returns session from context
// GetSession returns session from context.
func (s *CacheSessionStore) GetSession(ctx *azugo.Context) (*core.Session, error) {
	sess, ok := ctx.UserValue(SessionUserValueKey).(*core.Session)
	if !ok {
		return nil, nil
	}
	return sess, nil
}

const (
	SessionUserValueKey = "__Session"
	AuthorizationBearer = "bearer"
)

// ErrSessionNotFoundError is returned when session is not found.
type ErrSessionNotFoundError struct {
	SessionID string
}

func (e ErrSessionNotFoundError) Error() string {
	return "Session not found"
}

// InvalidOrganizationError is returned when session is not found.
type InvalidOrganizationError struct {
	Code string
}

func (e InvalidOrganizationError) Error() string {
	return "Invalid organization"
}

func (e InvalidOrganizationError) SafeError() string {
	return "Invalid organization"
}

func (e InvalidOrganizationError) StatusCode() int {
	return fasthttp.StatusBadRequest
}
