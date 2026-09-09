package apiv1

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/juanfont/headscale/hscontrol/types"
)

func init() {
	registrations = append(registrations, registerLock)
}

type (
	getLockStatusInput  struct{}
	getLockStatusOutput struct {
		Body types.TKALockStatus
	}

	getLockNodesInput  struct{}
	getLockNodesOutput struct {
		Body struct {
			Nodes []types.TKANodeLockStatus `json:"nodes"`
		}
	}
)

func registerLock(api huma.API, b Backend) {
	huma.Register(api, huma.Operation{
		OperationID: "getTailnetLockStatus",
		Method:      http.MethodGet,
		Path:        "/api/v1/lock",
		Summary:     "Get tailnet lock status",
		Description: "Reports overall tailnet lock state, head commit, trusted keys, and node statistics.",
		Tags:        []string{"TailnetLock"},
		Security:    bearerAuth,
	}, func(ctx context.Context, _ *getLockStatusInput) (*getLockStatusOutput, error) {
		return &getLockStatusOutput{Body: b.State.TKALockStatus()}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "getTailnetLockNodes",
		Method:      http.MethodGet,
		Path:        "/api/v1/lock/nodes",
		Summary:     "Get tailnet lock node status",
		Description: "Reports per-node tailnet lock status including signature and authorization state.",
		Tags:        []string{"TailnetLock"},
		Security:    bearerAuth,
	}, func(ctx context.Context, _ *getLockNodesInput) (*getLockNodesOutput, error) {
		nodes := b.State.TKANodesLockStatus()
		out := getLockNodesOutput{}
		out.Body.Nodes = nodes
		return &out, nil
	})
}
