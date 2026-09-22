package idauth

import (
	"context"
	"time"

	jsondb "github.com/lx-lib/lx-go-jsondb"
	"github.com/lx-lib/lx-idauth/core"
	"github.com/lx-lib/lx-idauth/core/util"

	"azugo.io/azugo"
	"azugo.io/core/cache"
	"github.com/oklog/ulid/v2"
	"github.com/valyala/fasthttp"
)

func NewAzugoCacheSessionStore(app *azugo.App, ttl time.Duration) (*CacheSessionStore, error) {
	store, err := cache.Create[*core.Session](app.Cache(), "idauth-session", cache.DefaultTTL(ttl))
	if err != nil {
		return nil, err
	}

	return &CacheSessionStore{
		store: store,
	}, nil
}

type PostgresSessionStoreConfig struct {
	Postgres *jsondb.Configuration `json:"postgres"`
}

func NewPostgresSessionStore(app *azugo.App, config *PostgresSessionStoreConfig) (*PostgresSessionStore, error) {
	store, _, err := jsondb.New(app.App, config.Postgres)
	if err != nil {
		return nil, err
	}

	return &PostgresSessionStore{
		Store: store,
	}, nil
}

type CacheSessionStore struct {
	store cache.Instance[*core.Session]
}

type PostgresSessionStore struct {
	Store jsondb.Store
}

type Response struct {
	Message string `json:"message"`
}

type Params struct {
	ID string `json:"id" validate:"ulid"`
}

type SessionExpiryRequest struct {
	Timeout time.Duration `json:"session_timeout"`
}

type GetUserSessionsRequest struct {
	ID      *string `json:"id" validate:"omitempty"`
	Code    string  `json:"code" validate:"required"`
	Page    *int    `json:"page,omitempty"`
	PerPage *int    `json:"perPage,omitempty"`
}

type deleteUserSessionRequest struct {
	ID string `json:"id" validate:"required"`
}

type sessionRequestFilter struct {
	ID              *string `json:"id"`
	Code            *string `json:"code"`
	FirstName       *string `json:"first_name"`
	LastName        *string `json:"last_name"`
	Email           *string `json:"email"`
	IsServiceClient *bool   `json:"is_service_client"`
	Subject         *string `json:"subject"`
	Role            *string `json:"role"`
	Organization    *string `json:"organization"`
	Page            *int    `json:"page,omitempty"`
	PerPage         *int    `json:"perPage,omitempty"`
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
	session.LastAccessed = util.PtrTime(time.Now().UTC())
	// Ignore session cache update error, session will be loaded automatically if not in cache
	_ = sp.store.Set(ctx, session.ID, session)
	return session, nil
}

func (sp *CacheSessionStore) Delete(ctx *azugo.Context, id string) error {
	return sp.store.Delete(ctx, id)
}

func (s *CacheSessionStore) GetSession(ctx *azugo.Context) (*core.Session, error) {
	sess, ok := ctx.UserValue(SessionUserValueKey).(*core.Session)
	if !ok {
		return nil, nil
	}
	return sess, nil
}

func (s *CacheSessionStore) StoreStart(app *azugo.App) error {
	return nil
}

func (s *CacheSessionStore) StoreStop() {
	// noop implementation
}

func (s *CacheSessionStore) DeleteExpiredSessions(ctx context.Context, sessionTimeout time.Duration) error {
	return nil
}

func (s *CacheSessionStore) GetUserSessions(ctx *azugo.Context, code string, id string) (*core.SessionsResponse, error) {
	return nil, nil
}

func (sp *CacheSessionStore) DeleteUserSession(ctx *azugo.Context, id string) error {
	return nil
}

func (s *CacheSessionStore) GetSessions(ctx *azugo.Context) ([]*core.Session, error) {
	return nil, nil
}

func (p *PostgresSessionStore) GetSessionByID(ctx *azugo.Context, id string) (*core.Session, error) {
	res := &core.Session{}
	params := &Params{
		ID: id,
	}
	if err := ctx.Validate().Struct(params); err != nil {
		ctx.Error(err)
		return nil, ErrSessionNotFoundError{id}
	}
	err := p.Store.Exec(ctx, "lx_idauth.get_session", params, res)
	if err != nil {
		return nil, ErrSessionNotFoundError{id}
	}

	return res, nil
}

func (p *PostgresSessionStore) Create(ctx *azugo.Context, session *core.Session) (*core.Session, error) {
	if session.ID == "" {
		session.ID = ulid.Make().String()
	}
	res := &Response{}
	err := p.Store.Exec(ctx, "lx_idauth.save_session", session, res)
	if err != nil {
		return nil, err
	}

	return session, nil
}

func (p *PostgresSessionStore) Update(ctx *azugo.Context, session *core.Session) (*core.Session, error) {
	if session.ID == "" {
		return nil, ErrSessionNotFoundError{session.ID}
	}
	res := &Response{}
	err := p.Store.Exec(ctx, "lx_idauth.save_session", session, res)
	if err != nil {
		return nil, err
	}

	return session, nil
}

func (p *PostgresSessionStore) Extend(ctx *azugo.Context, id string) (*core.Session, error) {
	session := &core.Session{}
	params := &Params{
		ID: id,
	}
	if err := ctx.Validate().Struct(params); err != nil {
		ctx.Error(err)
		return nil, ErrSessionNotFoundError{id}
	}
	err := p.Store.Exec(ctx, "lx_idauth.get_session", params, session)
	if err != nil {
		return nil, ErrSessionNotFoundError{id}
	}
	session.LastAccessed = util.PtrTime(time.Now().UTC())
	res := &Response{}
	err = p.Store.Exec(ctx, "lx_idauth.save_session", session, res)
	if err != nil {
		return nil, err
	}

	return session, nil
}

func (p *PostgresSessionStore) Delete(ctx *azugo.Context, id string) error {
	res := &Response{}
	params := &Params{
		ID: id,
	}
	if err := ctx.Validate().Struct(params); err != nil {
		ctx.Error(err)
		return ErrSessionNotFoundError{id}
	}
	err := p.Store.Exec(ctx, "lx_idauth.delete_session", params, res)

	return err
}

func (p *PostgresSessionStore) GetSession(ctx *azugo.Context) (*core.Session, error) {
	sess, ok := ctx.UserValue(SessionUserValueKey).(*core.Session)
	if !ok {
		return nil, nil
	}

	return sess, nil
}

func (p *PostgresSessionStore) StoreStart(app *azugo.App) error {
	err := p.Store.Start(app.BackgroundContext())
	return err
}

func (p *PostgresSessionStore) StoreStop() {
	p.Store.Close()
}

func (p *PostgresSessionStore) DeleteExpiredSessions(ctx context.Context, sessionTimeout time.Duration) error {
	err := p.Store.Exec(ctx, "lx_idauth.delete_expired_sessions", &SessionExpiryRequest{
		Timeout: sessionTimeout,
	}, nil)
	return err
}

func (p *PostgresSessionStore) GetUserSessions(ctx *azugo.Context, code string, id string) (*core.SessionsResponse, error) {
	page, err := ctx.Query.IntOptional("page")
	if err != nil {
		return nil, err
	}

	perPage, err := ctx.Query.IntOptional("perPage")
	if err != nil {
		return nil, err
	}

	var idPtr *string
	if id != "" {
		idPtr = &id
	}
	params := &GetUserSessionsRequest{
		ID:      idPtr,
		Code:    code,
		Page:    page,
		PerPage: perPage,
	}
	if err := ctx.Validate().Struct(params); err != nil {
		return nil, err
	}

	sessions := &core.SessionsResponse{}
	err = p.Store.Exec(ctx, "lx_idauth.get_user_sessions", params, sessions)
	if err != nil {
		return nil, err
	}

	return sessions, nil
}

func (p *PostgresSessionStore) DeleteUserSession(ctx *azugo.Context, id string) error {
	params := &deleteUserSessionRequest{
		ID: id,
	}
	if err := ctx.Validate().Struct(params); err != nil {
		ctx.Error(err)
		return err
	}
	err := p.Store.Exec(ctx, "lx_idauth.delete_user_session", params, nil)
	return err
}

func (p *PostgresSessionStore) GetSessions(ctx *azugo.Context) ([]*core.Session, error) {
	params := &sessionRequestFilter{}
	if err := ctx.Body.JSON(params); err != nil {
		ctx.Error(err)

		return nil, err
	}
	if err := ctx.Validate().Struct(params); err != nil {
		return nil, err
	}

	sessions := &core.SessionsResponse{}
	err := p.Store.Exec(ctx, "lx_idauth.get_sessions", params, sessions)
	if err != nil {
		return nil, err
	}

	return sessions.List, nil
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
