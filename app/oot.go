package app

import (
	"crypto/rand"
	"time"

	"github.com/nobid-lsp-latvia/lx-idauth/core"

	"azugo.io/azugo"
	"azugo.io/core/cache"
	"github.com/oklog/ulid/v2"
	"go.uber.org/zap"
)

const ottCache = "idauth-ott"

// OTTStore manages the generation and exchange of one-time tokens.
type OTTStore struct {
	ch      cache.Instance[*core.OneTimeToken]
	entropy *ulid.MonotonicEntropy
}

// NewAzugoCacheOOTStore creates a new One Time Token store in order to generate and exchange one time tokens.
func NewAzugoCacheOOTStore(app *azugo.App) (*OTTStore, error) {
	sid := &OTTStore{}

	var err error
	sid.ch, err = cache.Create[*core.OneTimeToken](app.Cache(), ottCache,
		cache.DefaultTTL(3*time.Minute),
	)
	if err != nil {
		return nil, err
	}
	sid.entropy = ulid.Monotonic(rand.Reader, 0)
	return sid, nil
}

// GenerateToken creates a new one-time token and associates it with the given value.
func (st *OTTStore) GenerateToken(ctx *azugo.Context, session *core.Correlation) (*core.OneTimeToken, error) {
	ottULID, err := ulid.New(ulid.Timestamp(time.Now().UTC()), st.entropy)
	if err != nil {
		return nil, err
	}
	ott := ottULID.String()
	oneTimeToken := &core.OneTimeToken{
		ID:           ott,
		RedirectURI:  session.RedirectURI,
		SessionToken: session.ID,
	}
	if err := st.ch.Set(ctx, ott, oneTimeToken); err != nil {
		return nil, err
	}
	return oneTimeToken, nil
}

func (st *OTTStore) GetToken(ctx *azugo.Context, token string) (*core.OneTimeToken, error) {
	return st.ch.Get(ctx, token)
}

func (st *OTTStore) RedeemToken(ctx *azugo.Context, token string) (*core.OneTimeToken, error) {
	value, err := st.GetToken(ctx, token)
	if err != nil {
		return nil, err
	}

	if err = st.ch.Delete(ctx, token); err != nil {
		ctx.Log().Error("failed to delete token", zap.Error(err))
	}
	return value, nil
}
