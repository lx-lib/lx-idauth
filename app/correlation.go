package app

import (
	"crypto/rand"
	"time"

	"github.com/nobid-lsp-latvia/lx-idauth/core"

	"azugo.io/azugo"
	"azugo.io/core/cache"
	"github.com/oklog/ulid/v2"
	"github.com/valyala/fasthttp"
)

const DefaultCookieName = "idauth-correlation"

// CorrelationStore is a store for request correlations.
type CorrelationStore struct {
	app        *azugo.App
	ch         cache.Instance[*core.Correlation]
	cookieName string
	entropy    *ulid.MonotonicEntropy
}

// NewAzugoCacheCorrelationStore creates a new correlation store.
func NewAzugoCacheCorrelationStore(app *azugo.App) (*CorrelationStore, error) {
	ch, err := cache.Create[*core.Correlation](app.Cache(), "idauth-correlation", cache.DefaultTTL(20*time.Minute))
	if err != nil {
		return nil, err
	}

	return &CorrelationStore{
		app:        app,
		ch:         ch,
		cookieName: DefaultCookieName,
		entropy:    ulid.Monotonic(rand.Reader, 0),
	}, nil
}

// Set creates a new or updates existing correlation and sets it to the cookie.
func (s *CorrelationStore) Set(ctx *azugo.Context, correlation *core.Correlation) (*core.Correlation, error) {
	cor, id, err := s.getFromCookie(ctx)
	if err != nil {
		return nil, err
	}
	if cor != nil && correlation.ClientID != cor.ClientID {
		cor = nil
	}

	if cor == nil {
		// New correlation
		nid, err := ulid.New(ulid.Timestamp(time.Now().UTC()), s.entropy)
		if err != nil {
			return nil, err
		}
		id = nid.String()
		cor = &core.Correlation{
			ClientID:            correlation.ClientID,
			RedirectURI:         correlation.RedirectURI,
			Nonce:               correlation.Nonce,
			State:               correlation.State,
			CodeChallenge:       correlation.CodeChallenge,
			CodeChallengeMethod: correlation.CodeChallengeMethod,
		}
	} else {
		cor.ID = correlation.ID
		cor.ErrorCode = correlation.ErrorCode
	}

	if err := s.setToCookie(ctx, id, cor); err != nil {
		return nil, err
	}
	return cor, nil
}

// Get returns a correlation from the cookie.
func (s *CorrelationStore) Get(ctx *azugo.Context) (*core.Correlation, error) {
	cor, _, err := s.getFromCookie(ctx)
	if err != nil {
		return nil, err
	}
	return cor, nil
}

// Delete correlation from the cache and cookie.
func (s *CorrelationStore) Delete(ctx *azugo.Context) error {
	return s.deleteFromCookie(ctx)
}

func (s *CorrelationStore) getFromCookie(ctx *azugo.Context) (*core.Correlation, string, error) {
	buf := ctx.Context().Request.Header.Cookie(s.cookieName)
	if buf == nil {
		return nil, "", nil
	}
	c := fasthttp.AcquireCookie()

	defer fasthttp.ReleaseCookie(c)

	if err := c.ParseBytes(buf); err != nil {
		return nil, "", err
	}

	id := string(c.Value())

	cor, err := s.ch.Get(ctx, id)
	if err != nil || cor == nil {
		return nil, "", err
	}

	return cor, id, nil
}

func (s *CorrelationStore) setToCookie(ctx *azugo.Context, id string, correlation *core.Correlation) error {
	if err := s.ch.Set(ctx, id, correlation); err != nil {
		return err
	}

	c := fasthttp.AcquireCookie()
	defer fasthttp.ReleaseCookie(c)

	c.SetKey(s.cookieName)
	c.SetValue(id)
	c.SetSecure(ctx.IsTLS())
	c.SetHTTPOnly(true)
	// This is needed to make cookie work when request coming from external authorization
	c.SetSameSite(fasthttp.CookieSameSiteNoneMode)
	c.SetPath(ctx.BasePath())

	ctx.Context().Response.Header.SetCookie(c)

	return nil
}

func (s *CorrelationStore) deleteFromCookie(ctx *azugo.Context) error {
	buf := ctx.Context().Request.Header.Cookie(s.cookieName)
	if buf == nil {
		return nil
	}

	c := fasthttp.AcquireCookie()
	defer fasthttp.ReleaseCookie(c)

	if err := c.ParseBytes(buf); err != nil {
		return err
	}

	id := string(c.Value())

	err := s.ch.Delete(ctx, id)
	if err != nil {
		return err
	}

	c.SetKey(s.cookieName)
	c.SetSecure(ctx.IsTLS())
	c.SetHTTPOnly(true)
	// This is needed to make cookie work when request coming from external authorization
	c.SetSameSite(fasthttp.CookieSameSiteNoneMode)
	c.SetPath(ctx.BasePath())
	c.SetExpire(fasthttp.CookieExpireDelete)

	ctx.Context().Response.Header.SetCookie(c)
	return nil
}
