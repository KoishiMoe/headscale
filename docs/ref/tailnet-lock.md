# Tailnet Lock (TKA) Reference & Maintenance Guide

This document describes the Tailnet Lock (Tailscale Key Authority / TKA) implementation in Headscale, including operational procedures, protocol internals confirmed against upstream source code, and guidance for maintainers rebasing this fork.

---

## 1. Upstream References & Tested Versions

| Component | Repository | Tested Version / Commit | Notes |
|:---|:---|:---|:---|
| **Tailscale Client** | [`tailscale/tailscale`](https://github.com/tailscale/tailscale) | `v1.103.0` (`4d5bcebe331f8ce1c9e836ec468205f2faeef3bf`) | Verified against CLI commands: `tailscale lock init`, `status`, `sign`, `disable` |
| **Headscale Base** | [`juanfont/headscale`](https://github.com/juanfont/headscale) | `v0.29.1` (`38722e5eebe401b61cfed89a99773e4a5ece4440`) | Integrated with copy-on-write `NodeStore`, `mapper.Batcher`, and `State` coordinator |
| **Go Toolchain** | Go | `go1.27.0` | Pinned in `go.mod` |
| **TKA Whitepaper** | Tailscale | [Tailnet lock whitepaper](https://tailscale.com/blog/tailnet-lock) | "Tailnet lock: cryptographic verification of tailnet key distribution" (Jan 5, 2026 version) |

### Key Upstream Source Locations in Tailscale

If Tailscale ever modifies TKA in future client releases, inspect these packages in `tailscale/tailscale`:
- `tailscale.com/tka`: Core cryptographic structures (`Authority`, `AUM`, `Chonk`, `NodeKeySignature`, `Key`, `Hash`).
- `tailscale.com/control/controlclient/auto.go`: Client-side HTTP requests over Noise to `/machine/tka/*`.
- `tailscale.com/ipn/localapi`: Local daemon API handlers servicing `tailscale lock` CLI commands (`handleTailnetLock*`).
- `tailscale.com/tailcfg`: Wire types (`TKAInfo`, `TKAInitBeginResponse`, `TKABootstrapResponse`, `TKASignRequest`, etc.).

---

## 2. Non-Public / Undocumented Implementation Details

The following facts were reverse-engineered and verified against the Tailscale client codebase and live smoke tests. They are not explicitly documented in the public whitepaper or user documentation:

### A. Client Capability Requirement (`nodecap.TailnetLock`)
- **Discovery**: Official Tailscale clients (`tailscale` CLI / `tailscaled`) check `status.CapMap` on the local node.
- **Requirement**: If `"https://tailscale.com/cap/tailnet-lock"` (`nodecap.TailnetLock`) is not present in `MapResponse.Node.CapMap`, the CLI immediately fails with `tailnet lock is not enabled for this tailnet` and refuses to run `tailscale lock init`.
- **Location in Headscale**: Populated in `types.NodeView.TailNode()` (`hscontrol/types/node.go`).

### B. TS2021 Noise Transport for TKA Endpoints
- **Discovery**: TKA communication does **not** occur over the public HTTPS control API or gRPC. It is multiplexed over the TS2021 Noise connection established between `tailscaled` and the server.
- **Endpoints**:
  - `POST /machine/tka/init/begin`: Returns uncommitted node-key signatures for existing active nodes (`tailcfg.TKAInitBeginResponse`).
  - `POST /machine/tka/init/finish`: Commits the Genesis AUM and applies initial node signatures (`tailcfg.TKAInitFinishRequest`).
  - `GET /machine/tka/bootstrap`: Delivers the entire chain of AUMs to bootstrapping nodes (`tailcfg.TKABootstrapResponse`).
  - `POST /machine/tka/sync/offer` & `POST /machine/tka/sync/send`: Two-step consensus synchronization for propagating newly published AUMs.
  - `POST /machine/tka/sign`: Receives node signatures (`tka.NodeKeySignature`), verifies signature validity against the active TKA authority, persists to node, and triggers map broadcasts.
  - `POST /machine/tka/disable`: Consumes a raw disablement secret preimage, verifies that its SHA-256 hash matches a hash in the Genesis AUM, and disables TKA.
  - `POST /machine/tka/affected-sigs`: Returns node signatures requiring re-signing when signing keys or node keys rotate.
- **Location in Headscale**: Implemented in `hscontrol/noise.go` on `noiseServer`.

### C. MapResponse `TKAInfo` Streaming Semantics
- **Discovery**: Clients monitor `MapResponse.TKAInfo` on every long-poll map stream packet.
  - When enabled: `TKAInfo.Head` must contain the current authority head AUM hash (32 bytes).
  - When disabled: `TKAInfo.Disabled = true` must be set.
  - When bootstrapping: If a client receives a new head hash it does not know, it initiates a call to `/machine/tka/bootstrap` or `/machine/tka/sync/offer`.
- **Location in Headscale**: Injected by `MapResponseBuilder.WithTKAInfo(...)` in `hscontrol/mapper/builder.go` and triggered incrementally via `change.IncludeTKA` in `hscontrol/types/change/change.go`.

### D. Peer Key Signature Distribution
- **Discovery**: Each peer in `MapResponse.Peers` must include `tailcfg.Node.KeySignature`. When tailnet lock is active, the Tailscale WireGuard engine drops packets from any peer whose node key is not signed by a trusted TLK.
- **Location in Headscale**: Mapped in `types.NodeView.TailNode()` from `node.KeySignature` to `tailcfg.Node.KeySignature`.

### E. Disablement Secrets Verification
- **Discovery**: When `tailscale lock init --gen-disablements N` is run, the client generates random 32-byte preimages. Only `sha256(preimage)` is transmitted in the Genesis AUM. Disablement requires providing the raw preimage to `/machine/tka/disable`.
- **Location in Headscale**: Managed automatically by `tailscale.com/tka.Authority` via `dbChonk` in `hscontrol/state/tka.go`.

---

## 3. Headscale Architecture Integration

All changes follow the architectural guidelines in `AGENTS.md`:

```
┌─────────────────────────────────────────────────────────────────┐
│                      hscontrol/noise.go                         │
│   TS2021 Noise HTTP: /machine/tka/init, sign, sync, disable     │
└────────────────┬────────────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────────────┐
│                     hscontrol/state/tka.go                      │
│      tka.Authority + dbChonk (Atomic SQLite persistence)        │
│   tka_states (head, disabled) + tka_aums (parent_hash, data)    │
└────────────────┬────────────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────────────┐
│                 hscontrol/types/change/change.go                │
│    IncludeTKA bitmask: broadcasts TKAOnly updates to batcher    │
└────────────────┬────────────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────────────┐
│                    hscontrol/mapper/builder.go                  │
│       Builds MapResponse.TKAInfo + Node.KeySignature            │
└─────────────────────────────────────────────────────────────────┘
```

1. **Database Schema & Migrations**:
   - Added tables `tka_states` and `tka_aums` in `hscontrol/db/schema.sql`.
   - Added migration `202609081300-add-tailnet-lock-support` at the **end** of the migrations list in `hscontrol/db/db.go`.
   - Foreign keys are **never disabled** (`migrationsRequiringFKDisabled` was untouched).
2. **State Store (`hscontrol/state/tka.go`)**:
   - Uses `tailscale.com/tka.Mem` wrapped by `dbChonk` to persist state across server restarts.
   - All state mutations execute through transaction helper `hsdb.Write(...)`.
   - Node signatures and `TKAState` initialization are batched in a single database transaction in `TKAInitFinish`.
   - Dedicated unit tests in `hscontrol/state/tka_test.go` validate initialization, signing, multi-step sync, disablement, and restart durability.
3. **Type Definitions (`hscontrol/types/tka.go`)**:
   - `types.TKAState` and `types.TKAAUM` live in `hscontrol/types/tka.go`.
4. **Mapper & Batcher**:
   - `change.TKAOnly()` allows notifying clients of lock state changes without forcing a full route recomputation.

---

## 4. Maintenance & Upstream Rebase Checklist

When updating this fork against future upstream `juanfont/headscale` releases or upstream `tailscale/tailscale` changes, use the following checklist:

### A. If Upstream Headscale Refactors `hscontrol/state/`
- **Check `State` coordinator**: Verify that `s.initTKA()` is invoked during `NewState(...)` in `hscontrol/state/state.go`.
- **Check `nodeUpdateColumns`**: Verify that `"KeySignature"` and `"NLKey"` remain in `nodeUpdateColumns` so GORM does not discard them on partial updates.
- **Check `NodeStore` / views**: Verify that `KeySignature` and `NLKey` accessors exist in generated view/clone files (`hscontrol/types/types_view.go`, `hscontrol/types/types_clone.go`). If types change, regenerate them using `go generate ./hscontrol/types/...`.

### B. If Upstream Headscale Refactors `hscontrol/types/change/`
- Check `hscontrol/types/change/change.go`:
  - Ensure `IncludeTKA bool` is preserved in `Change` struct.
  - Check `boolFieldNames()`, `Merge()`, `IsEmpty()`, `IsFull()`, `Type()`, and constructors (`TKAOnly()`).
  - Run `go test ./hscontrol/types/change/...` to ensure bitmask synchronizer tests pass.

### C. If Upstream Headscale Refactors `hscontrol/mapper/`
- Check `hscontrol/mapper/builder.go`: Ensure `WithTKAInfo(...)` sets `resp.TKAInfo`.
- Check `hscontrol/mapper/tail_test.go`: Ensure baseline capability assertions in `TestTailNode` and `TestTailNodeBaselineGates` expect `nodecap.TailnetLock`.

### D. If Upstream Headscale Adds New Database Migrations
- Check `hscontrol/db/db.go`:
  - Ensure `202609081300-add-tailnet-lock-support` maintains its timestamp and relative order among existing migrations.
  - If upstream added migrations with later timestamps, our migration stays right where it was committed (migration history is immutable).
  - Run `go test ./hscontrol/db/...` (which executes SQLite and squibble migration validation tests).

### E. Quick Smoke Test Verification
To verify the implementation after a rebase without needing Docker:
1. Build Headscale: `go build ./cmd/headscale`
2. Start test server with local SQLite and DERP map.
3. Start two Tailscale client nodes in userspace networking mode:
   ```bash
   tailscaled --tun=userspace-networking --socket=/tmp/node1.sock --port=41111
   tailscale --socket=/tmp/node1.sock up --login-server=http://127.0.0.1:8080 --authkey=<key>
   ```
4. Verify `tailscale --socket=/tmp/node1.sock lock status`.
5. Run `tailscale --socket=/tmp/node1.sock lock init --confirm --gen-disablements 1 <node1-tlpub>`.
6. Verify status transitions to `Tailnet Lock is ENABLED`.
7. Run `tailscale --socket=/tmp/node1.sock lock disable <secret>`.
8. Verify status transitions back to `Tailnet Lock is NOT enabled`.
