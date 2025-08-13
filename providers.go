package idauth

import (
	"fmt"
	"strings"

	"github.com/nobid-lsp-latvia/lx-idauth/core"
)

// Register makes a authentification provider available by the provided name.
// If Register is called twice with the same name or if provider is nil,
// it panics.
func (a *IDAuth) Register(name string, provider core.AuthProvider) {
	a.authProvidersMu.Lock()
	defer a.authProvidersMu.Unlock()

	if provider == nil {
		panic("idauth: register driver is nil")
	}

	name = strings.ToLower(name)

	if _, dup := a.authProviders[name]; dup {
		panic("idauth: register called twice for driver " + name)
	}
	a.authProviders[name] = provider
}

func (a *IDAuth) GetProvider(name string) (core.AuthProvider, error) {
	a.authProvidersMu.RLock()
	defer a.authProvidersMu.RUnlock()

	name = strings.ToLower(name)

	provider, ok := a.authProviders[name]
	if !ok {
		return nil, fmt.Errorf("idauth: unknown provider %q (forgotten import?)", name)
	}
	return provider, nil
}
