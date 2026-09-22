package idauth

import (
	"github.com/lx-lib/lx-idauth/core"

	"azugo.io/azugo"
	"github.com/valyala/fasthttp"
)

func (a *IDAuth) getUserSessions(ctx *azugo.Context) {
	userCode := ctx.UserValue(SessionUserValueKey).(*core.Session).Code
	sessions, err := a.sessionStore.GetUserSessions(ctx, userCode, "")
	if err != nil {
		ctx.Error(err)
		return
	}
	ctx.JSON(sessions)
}

func (a *IDAuth) deleteUsersSession(ctx *azugo.Context) {
	sessionId := ctx.Params.String("id")
	if err := a.sessionStore.DeleteUserSession(ctx, sessionId); err != nil {
		ctx.Error(err)
		return
	}
}

func (a *IDAuth) getSessions(ctx *azugo.Context) {
	sessions, err := a.sessionStore.GetSessions(ctx)
	if err != nil {
		ctx.Error(err)
		return
	}

	ctx.JSON(sessions)
}

func (a *IDAuth) deleteUserSession(ctx *azugo.Context) {
	userCode := ctx.UserValue(SessionUserValueKey).(*core.Session).Code
	sessionId := ctx.Params.String("id")
	sessions, err := a.sessionStore.GetUserSessions(ctx, userCode, sessionId)
	if err != nil {
		ctx.Error(err)
		return
	}
	if len(sessions.List) == 0 {
		ctx.StatusCode(fasthttp.StatusForbidden)
		return
	}
	if err := a.sessionStore.DeleteUserSession(ctx, sessionId); err != nil {
		ctx.Error(err)
		return
	}
}
