package hscontrol

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/tka"
	"tailscale.com/types/key"
	"tailscale.com/types/tkatype"
)

type tkaTestSigner struct {
	pub  tka.Key
	priv ed25519.PrivateKey
}

func (s *tkaTestSigner) SignAUM(h tkatype.AUMSigHash) ([]tkatype.Signature, error) {
	sig := ed25519.Sign(s.priv, h[:])
	return []tkatype.Signature{
		{
			KeyID:     s.pub.MustID(),
			Signature: sig,
		},
	}, nil
}

func makeTestTLK(t *testing.T) (tka.Key, ed25519.PrivateKey, *tkaTestSigner) {
	t.Helper()
	pubBytes, privBytes, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	tKey := tka.Key{
		Kind:   tka.Key25519,
		Votes:  1,
		Public: pubBytes,
	}
	signer := &tkaTestSigner{pub: tKey, priv: privBytes}
	return tKey, privBytes, signer
}

func signNodeKey(t *testing.T, nodeKey key.NodePublic, tKey tka.Key, priv ed25519.PrivateKey) []byte {
	t.Helper()
	pubBin, err := nodeKey.MarshalBinary()
	require.NoError(t, err)

	nks := tka.NodeKeySignature{
		SigKind: tka.SigDirect,
		Pubkey:  pubBin,
		KeyID:   tKey.MustID(),
	}
	h := nks.SigHash()
	nks.Signature = ed25519.Sign(priv, h[:])
	return nks.Serialize()
}

func TestAPIV1Lock(t *testing.T) {
	h := newAPIV1Harness(t)

	t.Run("lock status disabled initially", func(t *testing.T) {
		res := h.callHuma(http.MethodGet, "/api/v1/lock", nil)
		assert.Equal(t, http.StatusOK, res.status)

		var status types.TKALockStatus
		err := json.Unmarshal(res.body, &status)
		require.NoError(t, err)
		assert.False(t, status.ConfigEnabled)
		assert.False(t, status.Enabled)
		assert.Equal(t, 0, status.Summary.TotalNodes)
	})

	t.Run("lock nodes empty initially", func(t *testing.T) {
		res := h.callHuma(http.MethodGet, "/api/v1/lock/nodes", nil)
		assert.Equal(t, http.StatusOK, res.status)

		var output struct {
			Nodes []types.TKANodeLockStatus `json:"nodes"`
		}
		err := json.Unmarshal(res.body, &output)
		require.NoError(t, err)
		assert.Empty(t, output.Nodes)
	})

	t.Run("lock status after tka init and node registration", func(t *testing.T) {
		h.app.cfg.TailnetLock.Enabled = true

		// Register a node first
		user := h.app.state.CreateUserForTest("lock-user")
		node := h.app.state.CreateRegisteredNodeForTest(user, "lock-box")
		h.app.state.PutNodeInStoreForTest(*node)

		// Bootstrap TKA on the state
		tKey, privKey, signer := makeTestTLK(t)
		disablementSecret := make([]byte, 32)
		_, err := rand.Read(disablementSecret)
		require.NoError(t, err)

		tkaState := tka.State{
			Keys:              []tka.Key{tKey},
			DisablementValues: [][]byte{tka.DisablementKDF(disablementSecret)},
		}
		storage := tka.ChonkMem()
		_, genesisAUM, err := tka.Create(storage, tkaState, signer)
		require.NoError(t, err)

		beginResp, err := h.app.state.TKAInitBegin(&tailcfg.TKAInitBeginRequest{
			GenesisAUM: genesisAUM.Serialize(),
		})
		require.NoError(t, err)
		require.Len(t, beginResp.NeedSignatures, 1)

		nodeKey := beginResp.NeedSignatures[0].NodePublic
		sig := signNodeKey(t, nodeKey, tKey, privKey)
		_, err = h.app.state.TKAInitFinish(&tailcfg.TKAInitFinishRequest{
			Signatures: map[tailcfg.NodeID]tkatype.MarshaledSignature{
				tailcfg.NodeID(node.ID): sig,
			},
			SupportDisablement: disablementSecret,
		})
		require.NoError(t, err)

		// Verify /api/v1/lock returns Enabled and summary
		resStatus := h.callHuma(http.MethodGet, "/api/v1/lock", nil)
		assert.Equal(t, http.StatusOK, resStatus.status)

		var status types.TKALockStatus
		err = json.Unmarshal(resStatus.body, &status)
		require.NoError(t, err)
		assert.True(t, status.ConfigEnabled)
		assert.True(t, status.Enabled)
		assert.NotEmpty(t, status.Head)
		assert.True(t, status.DisablementSecretConfigured)
		assert.Len(t, status.TrustedKeys, 1)
		assert.Equal(t, uint(1), status.TrustedKeys[0].Votes)
		assert.Equal(t, 1, status.Summary.TotalNodes)
		assert.Equal(t, 1, status.Summary.SignedNodes)
		assert.Equal(t, 1, status.Summary.AuthorizedNodes)
		assert.Equal(t, 0, status.Summary.UnsignedNodes)

		// Verify /api/v1/lock/nodes returns the node details
		resNodes := h.callHuma(http.MethodGet, "/api/v1/lock/nodes", nil)
		assert.Equal(t, http.StatusOK, resNodes.status)

		var output struct {
			Nodes []types.TKANodeLockStatus `json:"nodes"`
		}
		err = json.Unmarshal(resNodes.body, &output)
		require.NoError(t, err)
		require.Len(t, output.Nodes, 1)

		nodeLock := output.Nodes[0]
		assert.Equal(t, "lock-box", nodeLock.Hostname)
		assert.True(t, nodeLock.Signed)
		assert.True(t, nodeLock.Authorized)
		assert.NotEmpty(t, nodeLock.SigningKeyID)
	})
}
