package state

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

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

func persistTestReopenTKA(t *testing.T, dbPath string, lockEnabled bool) (*State, error) {
	t.Helper()

	cfg := persistTestConfig(dbPath)
	cfg.TailnetLock.Enabled = lockEnabled

	s, err := NewState(cfg)
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { _ = s.Close() })

	return s, nil
}

func TestTKALifecycle(t *testing.T) {
	dbPath, s, nodeID := persistTestSetup(t)

	// 1. Initially disabled
	assert.False(t, s.TKAEnabled())
	assert.Nil(t, s.TKAInfo())

	// 2. Generate TLK and Genesis AUM
	tKey, privKey, signer := makeTestTLK(t)
	disablementSecret := make([]byte, 32)
	_, err := rand.Read(disablementSecret)
	require.NoError(t, err)

	state := tka.State{
		Keys:              []tka.Key{tKey},
		DisablementValues: [][]byte{tka.DisablementKDF(disablementSecret)},
	}
	storage := tka.ChonkMem()
	_, genesisAUM, err := tka.Create(storage, state, signer)
	require.NoError(t, err)

	// 2b. Verify TKAInitBegin is rejected when tailnet_lock.enabled is false in configuration
	_, err = s.TKAInitBegin(&tailcfg.TKAInitBeginRequest{
		GenesisAUM: genesisAUM.Serialize(),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tailnet lock is not enabled in server configuration")

	// Enable tailnet_lock in configuration
	s.cfg.TailnetLock.Enabled = true

	// 3. TKAInitBegin succeeds once enabled in configuration
	beginResp, err := s.TKAInitBegin(&tailcfg.TKAInitBeginRequest{
		GenesisAUM: genesisAUM.Serialize(),
	})
	require.NoError(t, err)
	require.Len(t, beginResp.NeedSignatures, 1)
	assert.Equal(t, tailcfg.NodeID(nodeID), beginResp.NeedSignatures[0].NodeID)

	nodeKey := beginResp.NeedSignatures[0].NodePublic

	// 4. TKAInitFinish
	sig := signNodeKey(t, nodeKey, tKey, privKey)
	finishChange, err := s.TKAInitFinish(&tailcfg.TKAInitFinishRequest{
		Signatures: map[tailcfg.NodeID]tkatype.MarshaledSignature{
			tailcfg.NodeID(nodeID): sig,
		},
		SupportDisablement: nil, // Standard client init does not send SupportDisablement
	})
	require.NoError(t, err)
	assert.True(t, finishChange.IsFull())

	assert.True(t, s.TKAEnabled())
	assert.Equal(t, 1, s.TKALockStatus().DisablementSecretsCount)
	info := s.TKAInfo()
	require.NotNil(t, info)
	assert.NotEmpty(t, info.Head)
	assert.False(t, info.Disabled)

	// Verify node signature in store
	n, ok := s.GetNodeByID(nodeID)
	require.True(t, ok)
	assert.Equal(t, []byte(sig), []byte(n.KeySignature().AsSlice()))

	// 4b. Verify that closing and reopening with tailnet_lock disabled is rejected because network is locked
	originalHead := info.Head
	require.NoError(t, s.Close())

	_, err = persistTestReopenTKA(t, dbPath, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot disable tailnet lock in configuration: network is currently locked")

	// 5. Test persistence across server restart with tailnet_lock enabled
	s2, err := persistTestReopenTKA(t, dbPath, true)
	require.NoError(t, err)
	assert.True(t, s2.TKAEnabled())
	info2 := s2.TKAInfo()
	require.NotNil(t, info2)
	assert.Equal(t, originalHead, info2.Head)
	assert.Equal(t, 1, s2.TKALockStatus().DisablementSecretsCount)

	n2, ok := s2.GetNodeByID(nodeID)
	require.True(t, ok)
	assert.Equal(t, []byte(sig), []byte(n2.KeySignature().AsSlice()))

	// 6. Test TKABootstrap
	bootstrapResp, err := s2.TKABootstrap()
	require.NoError(t, err)
	assert.NotEmpty(t, bootstrapResp.GenesisAUM)

	// 7. Test TKASign for a newly registered node
	node2Key := key.NewNode()
	user, err := s2.GetUserByID(1)
	require.NoError(t, err)

	newNode := s2.CreateRegisteredNodeForTest(user, "node-2")
	newNode.NodeKey = node2Key.Public()
	require.NoError(t, s2.DB().DB.Save(newNode).Error)
	newNodeView := s2.PutNodeInStoreForTest(*newNode)
	assert.Empty(t, newNodeView.KeySignature().AsSlice())

	node2Sig := signNodeKey(t, node2Key.Public(), tKey, privKey)
	signChange, err := s2.TKASign(&tailcfg.TKASubmitSignatureRequest{
		Signature: node2Sig,
	})
	require.NoError(t, err)
	assert.True(t, signChange.IsFull())

	newNodeUpdated, ok := s2.GetNodeByID(newNode.ID)
	require.True(t, ok)
	assert.Equal(t, []byte(node2Sig), []byte(newNodeUpdated.KeySignature().AsSlice()))

	// 8. Test TKAAffectedSigs
	affectedResp, err := s2.TKAAffectedSigs(&tailcfg.TKASignaturesUsingKeyRequest{
		KeyID: tKey.MustID(),
	})
	require.NoError(t, err)
	assert.Len(t, affectedResp.Signatures, 2)

	// 9. Test TKADisable
	disableChange, err := s2.TKADisable(&tailcfg.TKADisableRequest{
		DisablementSecret: disablementSecret,
	})
	require.NoError(t, err)
	assert.True(t, disableChange.IsFull())

	assert.False(t, s2.TKAEnabled())
	disabledInfo := s2.TKAInfo()
	require.NotNil(t, disabledInfo)
	assert.True(t, disabledInfo.Disabled)

	// Verify node signatures are cleared in store
	nCleared, ok := s2.GetNodeByID(nodeID)
	require.True(t, ok)
	assert.Empty(t, nCleared.KeySignature().AsSlice())

	// 10. Test disablement persistence across restart: reopening with tailnet_lock disabled succeeds because network is unlocked
	require.NoError(t, s2.Close())
	tKeyReinit, privKeyReinit, signerReinit := makeTestTLK(t)
	disablementSecret2 := make([]byte, 32)
	_, err = rand.Read(disablementSecret2)
	require.NoError(t, err)

	stateReinit := tka.State{
		Keys:              []tka.Key{tKeyReinit},
		DisablementValues: [][]byte{tka.DisablementKDF(disablementSecret2)},
	}
	storageReinit := tka.ChonkMem()
	_, genesisAUM2, err := tka.Create(storageReinit, stateReinit, signerReinit)
	require.NoError(t, err)

	s3Disabled, err := persistTestReopenTKA(t, dbPath, false)
	require.NoError(t, err)
	assert.False(t, s3Disabled.TKAEnabled())
	assert.Nil(t, s3Disabled.TKAInfo())

	// When disabled in config, re-initialization is rejected
	_, err = s3Disabled.TKAInitBegin(&tailcfg.TKAInitBeginRequest{GenesisAUM: genesisAUM2.Serialize()})
	assert.ErrorContains(t, err, "tailnet lock is not enabled in server configuration")
	require.NoError(t, s3Disabled.Close())

	// 11. Test Re-initialization after disablement when enabled in config
	s3, err := persistTestReopenTKA(t, dbPath, true)
	require.NoError(t, err)
	assert.False(t, s3.TKAEnabled())
	disabledInfo3 := s3.TKAInfo()
	require.NotNil(t, disabledInfo3)
	assert.True(t, disabledInfo3.Disabled)

	beginResp2, err := s3.TKAInitBegin(&tailcfg.TKAInitBeginRequest{
		GenesisAUM: genesisAUM2.Serialize(),
	})
	require.NoError(t, err)
	require.NotEmpty(t, beginResp2.NeedSignatures)

	nodeKeyReinit := beginResp2.NeedSignatures[0].NodePublic
	reinitSig := signNodeKey(t, nodeKeyReinit, tKeyReinit, privKeyReinit)

	reinitChange, err := s3.TKAInitFinish(&tailcfg.TKAInitFinishRequest{
		Signatures: map[tailcfg.NodeID]tkatype.MarshaledSignature{
			tailcfg.NodeID(nodeID): reinitSig,
		},
		SupportDisablement: nil,
	})
	require.NoError(t, err)
	assert.True(t, reinitChange.IsFull())

	assert.True(t, s3.TKAEnabled())
	assert.Equal(t, 1, s3.TKALockStatus().DisablementSecretsCount)
	reinitInfo := s3.TKAInfo()
	require.NotNil(t, reinitInfo)
	assert.NotEmpty(t, reinitInfo.Head)
	assert.False(t, reinitInfo.Disabled)

	nReinit, ok := s3.GetNodeByID(nodeID)
	require.True(t, ok)
	assert.Equal(t, []byte(reinitSig), []byte(nReinit.KeySignature().AsSlice()))

	// Reopen after reinitialization to ensure DisablementSecretsCount stays true and DB is not contaminated
	require.NoError(t, s3.Close())
	s4, err := persistTestReopenTKA(t, dbPath, true)
	require.NoError(t, err)
	assert.True(t, s4.TKAEnabled())
	assert.Equal(t, 1, s4.TKALockStatus().DisablementSecretsCount)
	assert.Nil(t, s4.tkaDisablementSecret)
}

func TestTKAValidationErrors(t *testing.T) {
	_, s, _ := persistTestSetup(t)
	defer s.Close()

	// Finish without Begin fails
	_, err := s.TKAInitFinish(&tailcfg.TKAInitFinishRequest{})
	assert.Error(t, err)

	// Invalid Genesis AUM fails
	_, err = s.TKAInitBegin(&tailcfg.TKAInitBeginRequest{GenesisAUM: []byte("invalid-aum")})
	assert.Error(t, err)

	// TKASign when not enabled fails
	_, err = s.TKASign(&tailcfg.TKASubmitSignatureRequest{Signature: []byte("sig")})
	assert.Error(t, err)

	// SupportDisablement is rejected to preserve zero-trust boundary
	tKeyErr, _, signerErr := makeTestTLK(t)
	tkaStateErr := tka.State{
		Keys:              []tka.Key{tKeyErr},
		DisablementValues: [][]byte{tka.DisablementKDF([]byte("secret"))},
	}
	_, genAUMErr, err := tka.Create(tka.ChonkMem(), tkaStateErr, signerErr)
	require.NoError(t, err)
	s.cfg.TailnetLock.Enabled = true
	_, err = s.TKAInitBegin(&tailcfg.TKAInitBeginRequest{GenesisAUM: genAUMErr.Serialize()})
	require.NoError(t, err)
	_, err = s.TKAInitFinish(&tailcfg.TKAInitFinishRequest{
		SupportDisablement: []byte("secret"),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--gen-disablement-for-support is not permitted on Headscale")
}

func TestTKASync(t *testing.T) {
	dbPath, s, nodeID := persistTestSetup(t)
	s.cfg.TailnetLock.Enabled = true

	tKey, privKey, signer := makeTestTLK(t)
	disablementSecret := make([]byte, 32)
	_, err := rand.Read(disablementSecret)
	require.NoError(t, err)

	state := tka.State{
		Keys:              []tka.Key{tKey},
		DisablementValues: [][]byte{tka.DisablementKDF(disablementSecret)},
	}
	storage := tka.ChonkMem()
	_, genesisAUM, err := tka.Create(storage, state, signer)
	require.NoError(t, err)

	beginResp, err := s.TKAInitBegin(&tailcfg.TKAInitBeginRequest{
		GenesisAUM: genesisAUM.Serialize(),
	})
	require.NoError(t, err)

	nodeKey := beginResp.NeedSignatures[0].NodePublic
	sig := signNodeKey(t, nodeKey, tKey, privKey)
	_, err = s.TKAInitFinish(&tailcfg.TKAInitFinishRequest{
		Signatures: map[tailcfg.NodeID]tkatype.MarshaledSignature{
			tailcfg.NodeID(nodeID): sig,
		},
		SupportDisablement: nil,
	})
	require.NoError(t, err)

	// Client-side authority initialized from genesis
	clientStorage := tka.ChonkMem()
	clientAuth, err := tka.Bootstrap(clientStorage, genesisAUM)
	require.NoError(t, err)

	// Client creates an update (adding key 2)
	tKey2, _, _ := makeTestTLK(t)
	updater := clientAuth.NewUpdater(signer)
	require.NoError(t, updater.AddKey(tKey2))
	updates, err := updater.Finalize(clientStorage)
	require.NoError(t, err)
	require.NoError(t, clientAuth.Inform(clientStorage, updates))

	// 1. Test TKASyncOffer
	clientOffer, err := clientAuth.SyncOffer(clientStorage)
	require.NoError(t, err)
	head, ancestors, err := tka.FromSyncOffer(clientOffer)
	require.NoError(t, err)

	offerResp, err := s.TKASyncOffer(&tailcfg.TKASyncOfferRequest{
		Head:      head,
		Ancestors: ancestors,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, offerResp.Head)

	// 2. Test TKASyncSend
	marshaledAUMs := make([]tkatype.MarshaledAUM, len(updates))
	for i, u := range updates {
		marshaledAUMs[i] = u.Serialize()
	}

	sendResp, ch, err := s.TKASyncSend(&tailcfg.TKASyncSendRequest{
		MissingAUMs: marshaledAUMs,
	})
	require.NoError(t, err)
	assert.False(t, ch.IsFull())

	clientHeadText, _ := clientAuth.Head().MarshalText()
	assert.Equal(t, string(clientHeadText), sendResp.Head)
	assert.Equal(t, string(clientHeadText), s.TKAInfo().Head)

	// 3. Test persistence of new Head after restart
	require.NoError(t, s.Close())
	s2, err := persistTestReopenTKA(t, dbPath, true)
	require.NoError(t, err)
	assert.True(t, s2.TKAEnabled())
	assert.Equal(t, string(clientHeadText), s2.TKAInfo().Head)
}
