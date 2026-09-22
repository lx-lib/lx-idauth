package app

import (
	"sync"
	"testing"

	"azugo.io/azugo"
	"github.com/lx-lib/lx-idauth/core"
)

func TestCorrelationStoreConcurrency(t *testing.T) {
	t.Parallel()

	ta := azugo.NewTestApp()
	ta.Start(t)
	defer ta.Stop()

	store, err := NewAzugoCacheCorrelationStore(ta.App)
	if err != nil {
		t.Fatalf("failed to create CorrelationStore: %v", err)
	}

	const goroutines = 20
	const perG = 2000

	start := make(chan struct{})
	panicCh := make(chan interface{}, goroutines)
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					panicCh <- r
				}
			}()
			<-start
			for i := 0; i < perG; i++ {
				ta.MockContext(func(ctx *azugo.Context) {
					nonce := "nonce"
					state := "state"
					cc := "cc"
					ccm := "S256"
					_, err := store.Set(ctx, &core.Correlation{
						ClientID:            "temp",
						RedirectURI:         "https://localhost:12345/auth-done",
						Nonce:               &nonce,
						State:               &state,
						CodeChallenge:       &cc,
						CodeChallengeMethod: &ccm,
					})
					if err != nil {
						t.Errorf("Set failed: %v", err)
					}
				})
			}
		}()
	}

	close(start)
	wg.Wait()
	close(panicCh)

	if p, ok := <-panicCh; ok {
		t.Fatalf("concurrent CorrelationStore.Set panicked: %v", p)
	}
}

func TestOTTStoreConcurrency(t *testing.T) {
	t.Parallel()

	ta := azugo.NewTestApp()
	ta.Start(t)
	defer ta.Stop()

	store, err := NewAzugoCacheOOTStore(ta.App)
	if err != nil {
		t.Fatalf("failed to create OTTStore: %v", err)
	}

	const goroutines = 20
	const perG = 2000

	start := make(chan struct{})
	panicCh := make(chan interface{}, goroutines)
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					panicCh <- r
				}
			}()
			<-start
			for i := 0; i < perG; i++ {
				ta.MockContext(func(ctx *azugo.Context) {
					_, err := store.GenerateToken(ctx, &core.Correlation{
						ID:          "AAAAAAAAAAAAAAAAAAAAAAAAAA",
						RedirectURI: "https://localhost:12345/auth-done",
					})
					if err != nil {
						t.Errorf("GenerateToken failed: %v", err)
					}
				})
			}
		}()
	}

	close(start)
	wg.Wait()
	close(panicCh)

	if p, ok := <-panicCh; ok {
		t.Fatalf("concurrent OTTStore.GenerateToken panicked: %v", p)
	}
}
