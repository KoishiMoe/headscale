package state

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	hsdb "github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"tailscale.com/tailcfg"
	"tailscale.com/tka"
	"tailscale.com/types/key"
	"tailscale.com/types/tkatype"
)

// dbChonk wraps an in-memory [tka.Mem] with persistent database storage.
type dbChonk struct {
	db  *hsdb.HSDatabase
	mem *tka.Mem
}

var _ tka.CompactableChonk = (*dbChonk)(nil)

func (c *dbChonk) AUM(hash tka.AUMHash) (tka.AUM, error) {
	return c.mem.AUM(hash)
}

func (c *dbChonk) ChildAUMs(prevAUMHash tka.AUMHash) ([]tka.AUM, error) {
	return c.mem.ChildAUMs(prevAUMHash)
}

func (c *dbChonk) CommitVerifiedAUMs(updates []tka.AUM) error {
	if len(updates) == 0 {
		return nil
	}

	_, err := hsdb.Write(c.db.DB, func(tx *gorm.DB) (any, error) {
		for _, a := range updates {
			hash := a.Hash()
			var parentHash string
			if a.PrevAUMHash != nil {
				parentHash = a.PrevAUMHash.String()
			}
			row := types.TKAAUM{
				Hash:       hash.String(),
				ParentHash: parentHash,
				Data:       a.Serialize(),
				CreatedAt:  time.Now(),
			}
			if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&row).Error; err != nil {
				return nil, err
			}
		}
		return nil, nil
	})
	if err != nil {
		return fmt.Errorf("persisting aums to db: %w", err)
	}

	return c.mem.CommitVerifiedAUMs(updates)
}

func (c *dbChonk) Heads() ([]tka.AUM, error) {
	return c.mem.Heads()
}

func (c *dbChonk) SetLastActiveAncestor(hash tka.AUMHash) error {
	return c.mem.SetLastActiveAncestor(hash)
}

func (c *dbChonk) LastActiveAncestor() (*tka.AUMHash, error) {
	return c.mem.LastActiveAncestor()
}

func (c *dbChonk) AllAUMs() ([]tka.AUMHash, error) {
	return c.mem.AllAUMs()
}

func (c *dbChonk) CommitTime(h tka.AUMHash) (time.Time, error) {
	return c.mem.CommitTime(h)
}

func (c *dbChonk) PurgeAUMs(hashes []tka.AUMHash) error {
	return nil
}

func (c *dbChonk) RemoveAll() error {
	_ = c.mem.RemoveAll()
	_, err := hsdb.Write(c.db.DB, func(tx *gorm.DB) (any, error) {
		return nil, tx.Exec("DELETE FROM tka_aums").Error
	})
	return err
}

// initTKA loads existing TKA state and AUMs from the database.
func (s *State) initTKA() error {
	s.tkaMu.Lock()
	defer s.tkaMu.Unlock()

	mem := tka.ChonkMem()
	s.tkaStorage = &dbChonk{
		db:  s.db,
		mem: mem,
	}

	// 1. Read TKA state from database
	var tkaState types.TKAState
	err := s.db.DB.First(&tkaState).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// Fresh database with no TKA state; ensure storage is clean
			_ = s.tkaStorage.RemoveAll()
			return nil
		}
		return fmt.Errorf("loading tka state: %w", err)
	}

	s.tkaDisablementSecret = tkaState.DisablementSecret

	// If TKA is not enabled, ensure storage and memory are completely clean
	if !tkaState.Enabled {
		_ = s.tkaStorage.RemoveAll()
		return nil
	}

	// Safety invariant: if the tailnet is locked, turning off tailnet_lock in configuration
	// is rejected at boot because the control server cannot unilaterally force-disable an
	// active cryptographic lock authority. The lock must first be disabled by an authorized
	// client using 'tailscale lock disable <secret>'.
	if s.cfg != nil && !s.cfg.TailnetLock.Enabled {
		return fmt.Errorf("cannot disable tailnet lock in configuration: network is currently locked. Tailnet lock must be disabled by an authorized client using 'tailscale lock disable <secret>' before setting tailnet_lock.enabled to false")
	}

	// 2. Read existing AUMs from database for enabled TKA
	var aumRows []types.TKAAUM
	err = s.db.DB.Find(&aumRows).Error
	if err != nil {
		return fmt.Errorf("loading tka aums: %w", err)
	}

	if len(aumRows) > 0 {
		aums := make([]tka.AUM, 0, len(aumRows))
		for _, row := range aumRows {
			var a tka.AUM
			if err := a.Unserialize(row.Data); err != nil {
				return fmt.Errorf("unserializing aum %s: %w", row.Hash, err)
			}
			aums = append(aums, a)
			if a.PrevAUMHash == nil {
				genesis := a
				s.tkaGenesisAUM = &genesis
			}
		}
		if err := mem.CommitVerifiedAUMs(aums); err != nil {
			return fmt.Errorf("committing loaded aums: %w", err)
		}

		auth, err := tka.Open(s.tkaStorage)
		if err != nil {
			return fmt.Errorf("opening tka authority: %w", err)
		}
		s.tkaAuthority = auth
		s.tkaEnabled = true
	}

	return nil
}

// TKAInfo returns the current TKAInfo to include in MapResponses.
func (s *State) TKAInfo() *tailcfg.TKAInfo {
	s.tkaMu.RLock()
	defer s.tkaMu.RUnlock()

	// Similar to noise.go:179, this check could be `s.cfg != nil && !s.cfg.TailnetLock.Enabled 
	// && !s.tkaEnabled` for defense, but currently simplified to match the startup behavior
	if s.cfg != nil && !s.cfg.TailnetLock.Enabled {
		return nil
	}

	if s.tkaEnabled && s.tkaAuthority != nil {
		head := s.tkaAuthority.Head()
		headText, err := head.MarshalText()
		if err != nil {
			return nil
		}
		return &tailcfg.TKAInfo{
			Head: string(headText),
		}
	}

	if len(s.tkaDisablementSecret) > 0 {
		return &tailcfg.TKAInfo{
			Disabled: true,
		}
	}

	return nil
}

// TKAEnabled reports whether tailnet lock is active.
func (s *State) TKAEnabled() bool {
	s.tkaMu.RLock()
	defer s.tkaMu.RUnlock()
	return s.tkaEnabled
}

// TKAInitBegin begins the initialization of tailnet lock.
func (s *State) TKAInitBegin(req *tailcfg.TKAInitBeginRequest) (*tailcfg.TKAInitBeginResponse, error) {
	s.tkaMu.Lock()
	defer s.tkaMu.Unlock()

	if s.cfg != nil && !s.cfg.TailnetLock.Enabled {
		return nil, errors.New("tailnet lock is not enabled in server configuration")
	}

	if s.tkaEnabled {
		return nil, errors.New("tailnet lock is already initialized")
	}

	// Clear any leftover AUMs in storage before initializing a new TKA
	if err := s.tkaStorage.RemoveAll(); err != nil {
		return nil, fmt.Errorf("clearing existing tka storage: %w", err)
	}
	s.tkaAuthority = nil
	s.tkaGenesisAUM = nil

	var aum tka.AUM
	if err := aum.Unserialize(req.GenesisAUM); err != nil {
		return nil, fmt.Errorf("invalid genesis AUM: %w", err)
	}

	s.pendingGenesisAUM = &aum

	var needSignatures []tailcfg.TKASignInfo
	for _, n := range s.ListNodes().All() {
		var rotationPubkey []byte
		if !n.NLKey().IsZero() {
			rotationPubkey = []byte(n.NLKey().Verifier())
		}
		needSignatures = append(needSignatures, tailcfg.TKASignInfo{
			NodeID:         tailcfg.NodeID(n.ID()),
			NodePublic:     n.NodeKey(),
			RotationPubkey: rotationPubkey,
		})
	}

	return &tailcfg.TKAInitBeginResponse{
		NeedSignatures: needSignatures,
	}, nil
}

// TKAInitFinish finalizes initialization of tailnet lock.
func (s *State) TKAInitFinish(req *tailcfg.TKAInitFinishRequest) (change.Change, error) {
	s.tkaMu.Lock()
	defer s.tkaMu.Unlock()

	if s.pendingGenesisAUM == nil {
		return change.Change{}, errors.New("no pending genesis AUM; call init/begin first")
	}

	// Ensure storage heads are empty before bootstrapping new authority
	if heads, err := s.tkaStorage.Heads(); err == nil && len(heads) > 0 {
		if err := s.tkaStorage.RemoveAll(); err != nil {
			return change.Change{}, fmt.Errorf("clearing tka storage before bootstrap: %w", err)
		}
	}

	auth, err := tka.Bootstrap(s.tkaStorage, *s.pendingGenesisAUM)
	if err != nil {
		return change.Change{}, fmt.Errorf("bootstrapping tka authority: %w", err)
	}

	s.tkaAuthority = auth
	s.tkaGenesisAUM = s.pendingGenesisAUM
	s.pendingGenesisAUM = nil
	s.tkaEnabled = true
	s.tkaDisablementSecret = req.SupportDisablement

	headText, _ := auth.Head().MarshalText()

	// Batch persist node signatures and TKAState in a single database transaction
	_, err = hsdb.Write(s.db.DB, func(tx *gorm.DB) (any, error) {
		for nodeID, sig := range req.Signatures {
			if err := tx.Model(&types.Node{}).
				Where("id = ?", uint64(nodeID)).
				Update("key_signature", []byte(sig)).Error; err != nil {
				return nil, fmt.Errorf("updating node %d signature: %w", nodeID, err)
			}
		}

		var stateRow types.TKAState
		if err := tx.First(&stateRow).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				stateRow = types.TKAState{
					Enabled:           true,
					Head:              string(headText),
					DisablementSecret: req.SupportDisablement,
				}
				if err := tx.Create(&stateRow).Error; err != nil {
					return nil, fmt.Errorf("creating tka state in db: %w", err)
				}
				return nil, nil
			}
			return nil, fmt.Errorf("reading tka state from db: %w", err)
		}

		stateRow.Enabled = true
		stateRow.Head = string(headText)
		if len(req.SupportDisablement) > 0 {
			stateRow.DisablementSecret = req.SupportDisablement
		}
		if err := tx.Save(&stateRow).Error; err != nil {
			return nil, fmt.Errorf("saving tka state in db: %w", err)
		}
		return nil, nil
	})
	if err != nil {
		return change.Change{}, fmt.Errorf("persisting tka initialization to db: %w", err)
	}

	// Once the DB transaction succeeds, update the in-memory NodeStore snapshots
	updates := make(map[types.NodeID]UpdateNodeFunc)
	for nodeID, sig := range req.Signatures {
		updates[types.NodeID(nodeID)] = func(n *types.Node) {
			n.KeySignature = sig
		}
	}
	if len(updates) > 0 {
		s.nodeStore.UpdateNodes(updates)
	}

	return change.FullUpdate(), nil
}

// TKABootstrap returns the bootstrap information for tailnet lock.
func (s *State) TKABootstrap() (*tailcfg.TKABootstrapResponse, error) {
	s.tkaMu.RLock()
	defer s.tkaMu.RUnlock()

	if s.tkaEnabled {
		if s.tkaGenesisAUM == nil {
			return nil, errors.New("no genesis AUM found")
		}
		return &tailcfg.TKABootstrapResponse{
			GenesisAUM: s.tkaGenesisAUM.Serialize(),
		}, nil
	}

	if len(s.tkaDisablementSecret) > 0 {
		return &tailcfg.TKABootstrapResponse{
			DisablementSecret: s.tkaDisablementSecret,
		}, nil
	}

	return nil, errors.New("tailnet lock is not enabled and no disablement secret")
}

// TKASyncOffer handles a client's sync offer and returns the server's sync offer and missing AUMs.
func (s *State) TKASyncOffer(req *tailcfg.TKASyncOfferRequest) (*tailcfg.TKASyncOfferResponse, error) {
	s.tkaMu.RLock()
	defer s.tkaMu.RUnlock()

	if !s.tkaEnabled || s.tkaAuthority == nil {
		return nil, errors.New("tailnet lock is not enabled")
	}

	nodeOffer, err := tka.ToSyncOffer(req.Head, req.Ancestors)
	if err != nil {
		return nil, fmt.Errorf("invalid node offer: %w", err)
	}

	controlOffer, err := s.tkaAuthority.SyncOffer(s.tkaStorage)
	if err != nil {
		return nil, fmt.Errorf("generating sync offer: %w", err)
	}

	sendAUMs, err := s.tkaAuthority.MissingAUMs(s.tkaStorage, nodeOffer)
	if err != nil {
		return nil, fmt.Errorf("computing missing AUMs: %w", err)
	}

	head, ancestors, err := tka.FromSyncOffer(controlOffer)
	if err != nil {
		return nil, fmt.Errorf("formatting sync offer: %w", err)
	}

	respMissing := make([]tkatype.MarshaledAUM, len(sendAUMs))
	for i, a := range sendAUMs {
		respMissing[i] = a.Serialize()
	}

	return &tailcfg.TKASyncOfferResponse{
		Head:        head,
		Ancestors:   ancestors,
		MissingAUMs: respMissing,
	}, nil
}

// TKASyncSend applies missing AUMs sent from a node to the authority.
func (s *State) TKASyncSend(req *tailcfg.TKASyncSendRequest) (*tailcfg.TKASyncSendResponse, change.Change, error) {
	s.tkaMu.Lock()
	defer s.tkaMu.Unlock()

	if !s.tkaEnabled || s.tkaAuthority == nil {
		return nil, change.Change{}, errors.New("tailnet lock is not enabled")
	}

	toApply := make([]tka.AUM, len(req.MissingAUMs))
	for i, a := range req.MissingAUMs {
		if err := toApply[i].Unserialize(a); err != nil {
			return nil, change.Change{}, fmt.Errorf("decoding missing AUM[%d]: %w", i, err)
		}
	}

	if len(toApply) > 0 {
		if err := s.tkaAuthority.Inform(s.tkaStorage, toApply); err != nil {
			return nil, change.Change{}, fmt.Errorf("inform authority: %w", err)
		}

		headText, _ := s.tkaAuthority.Head().MarshalText()
		_, err := hsdb.Write(s.db.DB, func(tx *gorm.DB) (any, error) {
			var stateRow types.TKAState
			if err := tx.First(&stateRow).Error; err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					stateRow = types.TKAState{
						Enabled: true,
						Head:    string(headText),
					}
					return nil, tx.Create(&stateRow).Error
				}
				return nil, err
			}
			stateRow.Head = string(headText)
			return nil, tx.Save(&stateRow).Error
		})
		if err != nil {
			return nil, change.Change{}, fmt.Errorf("persisting updated tka head in db: %w", err)
		}
	}

	headText, err := s.tkaAuthority.Head().MarshalText()
	if err != nil {
		return nil, change.Change{}, fmt.Errorf("marshaling head: %w", err)
	}

	resp := &tailcfg.TKASyncSendResponse{
		Head: string(headText),
	}

	return resp, change.TKAOnly(), nil
}

// TKASign verifies and persists a node-key signature.
func (s *State) TKASign(req *tailcfg.TKASubmitSignatureRequest) (change.Change, error) {
	s.tkaMu.RLock()
	defer s.tkaMu.RUnlock()

	if !s.tkaEnabled || s.tkaAuthority == nil {
		return change.Change{}, errors.New("tailnet lock is not enabled")
	}

	var sig tka.NodeKeySignature
	if err := sig.Unserialize(req.Signature); err != nil {
		return change.Change{}, fmt.Errorf("malformed signature: %w", err)
	}

	var keyBeingSigned key.NodePublic
	if err := keyBeingSigned.UnmarshalBinary(sig.Pubkey); err != nil {
		return change.Change{}, fmt.Errorf("malformed signature pubkey: %w", err)
	}

	if err := s.tkaAuthority.NodeKeyAuthorized(keyBeingSigned, req.Signature); err != nil {
		return change.Change{}, fmt.Errorf("signature does not verify: %w", err)
	}

	node, ok := s.GetNodeByNodeKey(keyBeingSigned)
	if !ok {
		return change.Change{}, errors.New("node not found")
	}

	updated, ok := s.nodeStore.UpdateNode(node.ID(), func(n *types.Node) {
		n.KeySignature = req.Signature
	})
	if !ok {
		return change.Change{}, errors.New("failed to update node in store")
	}

	if _, _, err := s.persistNodeToDB(updated); err != nil {
		return change.Change{}, fmt.Errorf("persisting signed node: %w", err)
	}

	return change.FullUpdate(), nil
}

// TKADisable disables tailnet lock across the tailnet using the disablement secret.
func (s *State) TKADisable(req *tailcfg.TKADisableRequest) (change.Change, error) {
	s.tkaMu.Lock()
	defer s.tkaMu.Unlock()

	if !s.tkaEnabled || s.tkaAuthority == nil {
		return change.Change{}, errors.New("tailnet lock is not enabled")
	}

	if !s.tkaAuthority.ValidDisablement(req.DisablementSecret) {
		return change.Change{}, errors.New("invalid disablement secret")
	}

	s.tkaEnabled = false
	s.tkaDisablementSecret = req.DisablementSecret
	s.tkaAuthority = nil
	s.tkaGenesisAUM = nil
	s.pendingGenesisAUM = nil

	// Permanently clear stored AUMs in memory and database
	if err := s.tkaStorage.RemoveAll(); err != nil {
		return change.Change{}, fmt.Errorf("clearing tka storage: %w", err)
	}

	_, err := hsdb.Write(s.db.DB, func(tx *gorm.DB) (any, error) {
		// Clear node signatures from previous authority
		if err := tx.Model(&types.Node{}).
			Where("key_signature IS NOT NULL").
			Update("key_signature", nil).Error; err != nil {
			return nil, fmt.Errorf("clearing node signatures: %w", err)
		}

		var stateRow types.TKAState
		if err := tx.First(&stateRow).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				stateRow = types.TKAState{
					Enabled:           false,
					DisablementSecret: req.DisablementSecret,
				}
				return nil, tx.Create(&stateRow).Error
			}
			return nil, err
		}
		stateRow.Enabled = false
		stateRow.Head = ""
		stateRow.DisablementSecret = req.DisablementSecret
		return nil, tx.Save(&stateRow).Error
	})
	if err != nil {
		return change.Change{}, fmt.Errorf("saving disabled tka state in db: %w", err)
	}

	// Clear node signatures in NodeStore
	updates := make(map[types.NodeID]UpdateNodeFunc)
	for _, n := range s.ListNodes().All() {
		if len(n.KeySignature().AsSlice()) > 0 {
			updates[n.ID()] = func(node *types.Node) {
				node.KeySignature = nil
			}
		}
	}
	if len(updates) > 0 {
		s.nodeStore.UpdateNodes(updates)
	}

	return change.FullUpdate(), nil
}

// TKAAffectedSigs queries all node signatures created with the specified keyID.
func (s *State) TKAAffectedSigs(req *tailcfg.TKASignaturesUsingKeyRequest) (*tailcfg.TKASignaturesUsingKeyResponse, error) {
	s.tkaMu.RLock()
	defer s.tkaMu.RUnlock()

	var matchingSigs []tkatype.MarshaledSignature

	for _, n := range s.ListNodes().All() {
		sigBytes := n.KeySignature().AsSlice()
		if len(sigBytes) == 0 {
			continue
		}
		var sig tka.NodeKeySignature
		if err := sig.Unserialize(sigBytes); err != nil {
			continue
		}
		if bytes.Equal(sig.KeyID, req.KeyID) {
			matchingSigs = append(matchingSigs, sigBytes)
		}
	}

	return &tailcfg.TKASignaturesUsingKeyResponse{
		Signatures: matchingSigs,
	}, nil
}

// TKANodesLockStatus returns the tailnet lock status of all nodes.
func (s *State) TKANodesLockStatus() []types.TKANodeLockStatus {
	s.tkaMu.RLock()
	auth := s.tkaAuthority
	enabled := s.tkaEnabled
	s.tkaMu.RUnlock()

	nodes := s.ListNodes()
	result := make([]types.TKANodeLockStatus, 0, nodes.Len())

	for _, n := range nodes.All() {
		sigBytes := n.KeySignature().AsSlice()
		signed := len(sigBytes) > 0
		authorized := false
		var signingKeyID string

		if signed {
			var sig tka.NodeKeySignature
			if err := sig.Unserialize(sigBytes); err == nil {
				if keyID, err := sig.UnverifiedAuthorizingKeyID(); err == nil {
					if len(keyID) == ed25519.PublicKeySize {
						signingKeyID = key.NLPublicFromEd25519Unsafe(ed25519.PublicKey(keyID)).CLIString()
					} else {
						signingKeyID = hex.EncodeToString(keyID)
					}
				}
			}
			if enabled && auth != nil {
				if err := auth.NodeKeyAuthorized(n.NodeKey(), tkatype.MarshaledSignature(sigBytes)); err == nil {
					authorized = true
				}
			}
		}

		var owner string
		if n.IsTagged() {
			owner = strings.Join(n.Tags().AsSlice(), ", ")
		} else if n.Owner().Valid() {
			owner = n.Owner().Name()
		}

		result = append(result, types.TKANodeLockStatus{
			ID:           n.StringID(),
			Hostname:     n.Hostname(),
			GivenName:    n.GivenName(),
			Owner:        owner,
			NodeKey:      n.NodeKey().String(),
			Signed:       signed,
			Authorized:   authorized,
			SigningKeyID: signingKeyID,
		})
	}

	return result
}

// TKALockStatus returns the overall tailnet lock status and key authority details.
func (s *State) TKALockStatus() types.TKALockStatus {
	s.tkaMu.RLock()
	defer s.tkaMu.RUnlock()

	status := types.TKALockStatus{
		ConfigEnabled:               s.cfg != nil && s.cfg.TailnetLock.Enabled,
		Enabled:                     s.tkaEnabled,
		DisablementSecretConfigured: len(s.tkaDisablementSecret) > 0,
		TrustedKeys:                 make([]types.TKATrustedKey, 0),
	}

	if s.tkaEnabled && s.tkaAuthority != nil {
		head := s.tkaAuthority.Head()
		if headText, err := head.MarshalText(); err == nil {
			status.Head = string(headText)
		}

		for _, k := range s.tkaAuthority.Keys() {
			var keyIDStr, pubStr string
			if id, err := k.ID(); err == nil {
				if len(id) == ed25519.PublicKeySize {
					keyIDStr = key.NLPublicFromEd25519Unsafe(ed25519.PublicKey(id)).CLIString()
				} else {
					keyIDStr = hex.EncodeToString(id)
				}
			}
			if len(k.Public) == ed25519.PublicKeySize {
				pubStr = key.NLPublicFromEd25519Unsafe(ed25519.PublicKey(k.Public)).CLIString()
			} else {
				pubStr = hex.EncodeToString(k.Public)
			}
			status.TrustedKeys = append(status.TrustedKeys, types.TKATrustedKey{
				KeyID:     keyIDStr,
				PublicKey: pubStr,
				Votes:     k.Votes,
				Kind:      k.Kind.String(),
				Metadata:  k.Meta,
			})
		}
	}

	// Calculate summary from nodes
	nodes := s.ListNodes()
	status.Summary.TotalNodes = nodes.Len()
	for _, n := range nodes.All() {
		sigBytes := n.KeySignature().AsSlice()
		signed := len(sigBytes) > 0
		if signed {
			status.Summary.SignedNodes++
			if s.tkaEnabled && s.tkaAuthority != nil {
				if err := s.tkaAuthority.NodeKeyAuthorized(n.NodeKey(), tkatype.MarshaledSignature(sigBytes)); err == nil {
					status.Summary.AuthorizedNodes++
				}
			}
		} else {
			status.Summary.UnsignedNodes++
		}
	}

	return status
}
