package idauth

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/lx-lib/lx-idauth/core/auth"

	jsonnet "github.com/google/go-jsonnet"
)

func TestJSONNetClaimMapper_MapSuccess(t *testing.T) {
	scriptPath := writeMappingScript(t, `function(input)
{
  person_code: input.claims.sub,
  first_name: input.claims.given_name,
  last_name: input.claims.family_name,
  email: input.claims.email,
}`)

	mapper, err := newJSONNetClaimMapper(scriptPath)
	if err != nil {
		t.Fatalf("new mapper: %v", err)
	}

	mapped, err := mapper.mapToAuthRequest(nil, &ClaimMappingInput{
		ProviderID:   "oidc-test",
		ProviderType: "oidc",
		RawToken:     "token-123",
		Claims: map[string]any{
			"sub":         "010101-10001",
			"given_name":  "John",
			"family_name": "Doe",
			"email":       "john.doe@example.org",
		},
	})
	if err != nil {
		t.Fatalf("map: %v", err)
	}

	if mapped.PersonCode != "010101-10001" {
		t.Fatalf("unexpected person code: %q", mapped.PersonCode)
	}
	if mapped.FirstName != "John" || mapped.LastName != "Doe" {
		t.Fatalf("unexpected name: %q %q", mapped.FirstName, mapped.LastName)
	}
	if mapped.Email != "john.doe@example.org" {
		t.Fatalf("unexpected email: %q", mapped.Email)
	}
	if mapped.Token != "token-123" {
		t.Fatalf("unexpected token: %q", mapped.Token)
	}
	if mapped.ProviderID != "oidc-test" {
		t.Fatalf("unexpected provider id: %q", mapped.ProviderID)
	}
}

func TestJSONNetClaimMapper_NullDeniesAuthorization(t *testing.T) {
	scriptPath := writeMappingScript(t, `function(input) null`)

	mapper, err := newJSONNetClaimMapper(scriptPath)
	if err != nil {
		t.Fatalf("new mapper: %v", err)
	}

	_, err = mapper.mapToAuthRequest(nil, &ClaimMappingInput{Claims: map[string]any{"sub": "1"}})
	if err == nil {
		t.Fatalf("expected error")
	}

	var authErr *auth.AuthorizeError
	if !errors.As(err, &authErr) {
		t.Fatalf("expected AuthorizeError, got %T", err)
	}
	if authErr.Code != auth.AuthErrInvalidRequest {
		t.Fatalf("unexpected error code: %s", authErr.Code)
	}
}

func TestJSONNetClaimMapper_ParallelStress(t *testing.T) {
	scriptPath := writeMappingScript(t, `function(input)
{
  person_code: input.claims.sub,
  first_name: input.claims.given_name,
  last_name: input.claims.family_name,
  email: input.claims.email,
}`)

	mapper, err := newJSONNetClaimMapper(scriptPath)
	if err != nil {
		t.Fatalf("new mapper: %v", err)
	}

	runParallelMapperCalls(t, mapper, 128, 50)
}

func TestJSONNetClaimMapper_UnsafeSharedVMRaceDemonstration(t *testing.T) {
	if os.Getenv("IDAUTH_RUN_UNSAFE_VM_RACE_TEST") != "1" {
		t.Skip("set IDAUTH_RUN_UNSAFE_VM_RACE_TEST=1 and run with -race to reproduce shared VM race")
	}

	scriptPath := writeMappingScript(t, `function(input)
{
  person_code: input.claims.sub,
  first_name: input.claims.given_name,
  last_name: input.claims.family_name,
  email: input.claims.email,
}`)

	mapper, err := newJSONNetClaimMapper(scriptPath)
	if err != nil {
		t.Fatalf("new mapper: %v", err)
	}

	sharedVM := jsonnet.MakeVM()
	mapper.vmPool = &sync.Pool{
		New: func() any {
			return sharedVM
		},
	}

	runParallelMapperCalls(t, mapper, 128, 50)
}

func runParallelMapperCalls(t *testing.T, mapper *jsonnetClaimMapper, workers, iterations int) {
	t.Helper()

	errCh := make(chan error, workers)
	var wg sync.WaitGroup

	for worker := 0; worker < workers; worker++ {
		worker := worker
		wg.Add(1)
		go func() {
			defer wg.Done()

			for idx := 0; idx < iterations; idx++ {
				sub := fmt.Sprintf("%03d-%03d", worker, idx)

				mapped, err := mapper.mapToAuthRequest(nil, &ClaimMappingInput{
					ProviderID: "oidc-test",
					RawToken:   "token",
					Claims: map[string]any{
						"sub":         sub,
						"given_name":  "John",
						"family_name": "Doe",
						"email":       "john.doe@example.org",
					},
				})
				if err != nil {
					select {
					case errCh <- fmt.Errorf("worker %d idx %d: %w", worker, idx, err):
					default:
					}
					return
				}

				if mapped.PersonCode != sub {
					select {
					case errCh <- fmt.Errorf("worker %d idx %d: expected person_code %q, got %q", worker, idx, sub, mapped.PersonCode):
					default:
					}
					return
				}
			}
		}()
	}

	wg.Wait()
	close(errCh)

	if err, ok := <-errCh; ok {
		t.Fatal(err)
	}
}

func writeMappingScript(t *testing.T, script string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "mapping.jsonnet")
	if err := os.WriteFile(path, []byte(script), 0o600); err != nil {
		t.Fatalf("write script: %v", err)
	}

	return path
}
