package idauth

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/lx-lib/lx-idauth/core"
	"github.com/lx-lib/lx-idauth/core/auth"

	"azugo.io/azugo"
	jsonnet "github.com/google/go-jsonnet"
)

type ClaimMappingInput struct {
	ProviderID   string            `json:"provider_id"`
	ProviderType string            `json:"provider_type"`
	Claims       map[string]any    `json:"claims"`
	Metadata     map[string]string `json:"metadata,omitempty"`
	Nonce        *string           `json:"nonce,omitempty"`
	RawToken     string            `json:"raw_token,omitempty"`
}

type jsonnetClaimMapper struct {
	filePath string
	script   string
	vmPool   *sync.Pool
}

type mappedAuthResult struct {
	core.AuthRequest
}

func newJSONNetClaimMapper(filePath string) (*jsonnetClaimMapper, error) {
	scriptBytes, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("read claim mapping file %q: %w", filePath, err)
	}

	script := strings.TrimSpace(string(scriptBytes))
	if script == "" {
		return nil, fmt.Errorf("claim mapping file %q is empty", filePath)
	}

	if _, err := jsonnet.SnippetToAST(filePath, script); err != nil {
		return nil, fmt.Errorf("parse claim mapping file %q: %w", filePath, err)
	}

	return &jsonnetClaimMapper{
		filePath: filePath,
		script:   script,
		vmPool: &sync.Pool{
			New: func() any {
				return jsonnet.MakeVM()
			},
		},
	}, nil
}

func (m *jsonnetClaimMapper) mapToAuthRequest(_ *azugo.Context, input *ClaimMappingInput) (*core.AuthRequest, error) {
	payload, err := json.Marshal(input)
	if err != nil {
		return nil, &auth.AuthorizeError{Code: auth.AuthErrServer, Message: "failed to encode claim mapping input"}
	}

	vm := m.vmPool.Get().(*jsonnet.VM)
	defer m.vmPool.Put(vm)
	vm.ExtReset() // stuff from other evals could be left over in the shared vm
	vm.TLAReset()

	eval := "local map = (" + m.script + "); map(" + string(payload) + ")"
	mapped, err := vm.EvaluateAnonymousSnippet(m.filePath, eval)
	if err != nil {
		return nil, &auth.AuthorizeError{Code: auth.AuthErrInvalidRequest, Message: "claim mapping evaluation failed"}
	}

	if strings.TrimSpace(mapped) == "null" {
		return nil, &auth.AuthorizeError{Code: auth.AuthErrInvalidRequest, Message: "authorization denied by claim mapping"}
	}

	result := &mappedAuthResult{}
	if err := json.Unmarshal([]byte(mapped), result); err != nil {
		return nil, &auth.AuthorizeError{Code: auth.AuthErrInvalidRequest, Message: "claim mapping output must be JSON object or null"}
	}

	result.Token = input.RawToken
	result.ProviderID = input.ProviderID
	result.RawClaims = input.Claims

	return &result.AuthRequest, nil
}
