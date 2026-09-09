package cli

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	clientv1 "github.com/juanfont/headscale/gen/client/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mockLockServer(
	t *testing.T,
	status clientv1.TKALockStatus,
	nodes []clientv1.TKANodeLockStatus,
) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/lock":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(status)
		case "/api/v1/lock/nodes":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(struct {
				Nodes []clientv1.TKANodeLockStatus `json:"nodes"`
			}{Nodes: nodes})
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestLockCLICommands(t *testing.T) {
	head := "test-head-hash-12345"
	keyID := "tlpub:abcdef1234567890"
	status := clientv1.TKALockStatus{
		Enabled:                     true,
		Head:                        &head,
		DisablementSecretConfigured: true,
		Summary: clientv1.TKASummary{
			TotalNodes:      2,
			SignedNodes:     1,
			AuthorizedNodes: 1,
			UnsignedNodes:   1,
		},
		TrustedKeys: &[]clientv1.TKATrustedKey{
			{
				KeyId:     keyID,
				PublicKey: keyID,
				Votes:     1,
				Kind:      "25519",
			},
		},
	}

	nodes := []clientv1.TKANodeLockStatus{
		{
			Id:           "1",
			Hostname:     "node-signed",
			GivenName:    "node-signed",
			Owner:        "user1",
			NodeKey:      "nodekey:abcdef",
			Signed:       true,
			Authorized:   true,
			SigningKeyId: &keyID,
		},
		{
			Id:         "2",
			Hostname:   "node-unsigned",
			GivenName:  "node-unsigned",
			Owner:      "user1",
			NodeKey:    "nodekey:123456",
			Signed:     false,
			Authorized: false,
		},
	}

	server := mockLockServer(t, status, nodes)
	defer server.Close()

	client, err := clientv1.NewClientWithResponses(server.URL)
	require.NoError(t, err)

	t.Run("get lock status response", func(t *testing.T) {
		res, err := client.GetTailnetLockStatusWithResponse(context.Background())
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, res.StatusCode())
		assert.True(t, res.JSON200.Enabled)
		assert.Equal(t, head, *res.JSON200.Head)
		assert.Equal(t, int64(2), res.JSON200.Summary.TotalNodes)
		assert.Equal(t, int64(1), res.JSON200.Summary.SignedNodes)
	})

	t.Run("get lock nodes response", func(t *testing.T) {
		res, err := client.GetTailnetLockNodesWithResponse(context.Background())
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, res.StatusCode())
		require.NotNil(t, res.JSON200.Nodes)
		assert.Len(t, *res.JSON200.Nodes, 2)
	})
}
