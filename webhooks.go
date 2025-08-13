package idauth

import (
	"azugo.io/azugo"
	"github.com/valyala/fasthttp"
)

func (a *IDAuth) clientsReload(ctx *azugo.Context) {
	// TODO: All active sessions for the clients which change/get deleted invalidated, but currently
	// a session doesnt store info about what client it belongs to

	// just a refetch should work for now 🤷‍♂️
	err := a.clientStore.RefetchClients()
	if err != nil {
		ctx.Error(err)
	}

	ctx.StatusCode(fasthttp.StatusOK)
}
