package app

import (
	"azugo.io/azugo"
)

type router struct {
	a *App
}

// Bind idauth routes to the specified endpoint.
func Bind(app *App, g azugo.Router) error {
	r := &router{
		a: app,
	}

	g.Get("/healthz", r.healthz)

	app.Auth().Bind(g)

	return nil
}
