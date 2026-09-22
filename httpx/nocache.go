package httpx

import "azugo.io/azugo"

func NoStore(next azugo.RequestHandler) azugo.RequestHandler {
	return func(ctx *azugo.Context) {
		ctx.Header.Set("Cache-Control", "no-store")
		next(ctx)
	}
}
