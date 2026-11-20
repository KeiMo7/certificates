# Multi-Root Coexistence and Rotation (`authority/rotation`)

This package gives a certificate authority a complete, self-contained root
rotation capability: several roots trusted at once, each with a trust window
and a one-way lifecycle, automatic time-based switch of the issuing root
without a restart, deterministic chain building, per-root CRLs, an atomic
online root-set reload, server-certificate coexistence during renewal, and
observability.

It depends only on the Go standard library and `crypto/x509` — **no new
external service**.

## Core concepts

- **Root window** — `NotBefore`/`NotAfter` (`RootConfig`). Inside the window a
  root is trusted; at/after `NotAfter` it verifies as retired; before
  `NotBefore` it reports a distinct "not yet valid" condition.
- **Lifecycle state** — `StateTrusted -> StateStopped -> StateRetired`
  (`types.go`). Transitions are one-way only; reloads that regress a state are
  rejected at load time. The clock can only narrow usability, never move the
  configured state backwards.
- **Snapshot** — the whole root set is an immutable `snapshot` reached through
  an `atomic.Pointer` (`manager.go`). Reads never see a half-applied change; a
  reload builds a validated candidate and only then swaps it in.

## Requirement map

### Covered forms (brief 一)

| # | Capability | API / location |
|---|------------|----------------|
| 1 | Multiple roots, each with effective/retire time; both trusted in window | `NewManager`, `RootConfig`, `rootEntry.inWindow` |
| 2 | New certs signed by current issuing root; automatic, restart-free switch | `Manager.Sign`, `Manager.ActiveIssuer` |
| 3 | Chain ordered leaf -> intermediate -> root; prefer non-retired, shortest | `Manager.BuildChain` (`chain.go`) |
| 4 | Client holding only old root verifies in window; explicit failure after | `Manager.Verify` with `VerifyOptions.TrustedRoots`, `ReasonRetired` |
| 5 | Retired root's still-valid certs identifiable; affected scope listed | `Manager.RootForCertificate`, `Manager.AffectedCertificates` |
| 6 | Server cert old+new coexist during renewal, both paths verify | `ServerCertRing` (`servercert.go`) |
| 7 | Public set distinguishes active issuer / trusted-not-issuing / retired | `Manager.Snapshot`, `RootView.Status` |
| 8 | Online root-set change; never a gap with no usable root | `Manager.Reload` (atomic swap, reject-then-keep-old) |
| 9 | Independent CRL entry per root, never overwritten by a switch | `Manager.SetRevoked/GetCRL/CRLStatus` (`crl.go`) |
| 10 | Observable window, remaining time, per-root issued count | `Manager.Snapshot` (`RootSet`, `RootView.Issued/Remaining`) |

### Hard constraints (brief 二)

1. **Always at least one issuable root.** Initial load requires a trusted,
   in-window root; reload/transition require a root with registered signing
   material that can issue now (`buildSnapshot`, `Transition`).
2. **Cert -> root is reverse-lookupable, not fingerprint-string matched.** An
   authoritative serial -> root index is written at signing (`leafIndex`);
   externally issued certs resolve via the standards-based AKI -> intermediate
   SKI -> root SKI walk (`snapshot.rootIDByAKI`, `byIntermediateSKI`).
3. **One-way state.** `State.canTransitionTo`; enforced on both `Transition`
   and every `Reload`.
4. **Verification independent of load order.** Roots are sorted
   deterministically (`sortEntries`: window start, then id); issuer selection
   and chain choice never depend on slice order.
5. **No new external dependency.** Stdlib + `crypto/x509` only.

### Failure / degradation (brief 三)

1. New root fails to load -> candidate rejected, current snapshot keeps
   serving (`Reload` returns, no swap).
2. Insufficient overlap / trust gap -> rejected at load with the conflicting
   roots named (`checkOverlaps`, `WithMinOverlap`).
3. CRL generation fails -> last good list retained, flagged `Stale`
   (`crlHolder`, `ReasonCRL` with `Stale: true`).
4. No usable root when building a chain -> typed error names the missing link
   (`ReasonNoRoot`/`ReasonBrokenChain`, `Error.MissingID`).

### Behavior that must not break (brief 四)

1. Single-root deployment is the same engine with one entry
   (`TestSingleRootParity`, `TestExternalAPISingleRootParity`).
2. The signing entry point takes a template + public key and returns leaf +
   ordered chain; existing request/response shapes are untouched.
3. The public root set still carries the original `*x509.Certificate`, so
   existing clients that parse only the certificate bytes keep working;
   status/window fields are additive.

## Explainable errors

All failures are `*rotation.Error` with a stable `Reason`
(`errors.go`): `invalid_config`, `no_issuing_root`, `untrusted_root`,
`root_retired`, `root_not_yet_valid`, `broken_chain`, `reload_rejected`,
`crl_generation_failed`. `RootID` and `MissingID` name the root and, when
relevant, the exact absent chain link.

## Tests

`go test ./authority/rotation/` — acceptance + unit tests using real generated
root/intermediate/leaf certificates:

- `TestDualRootWindowBothTrusted` — both roots verify; load-order independence.
- `TestOldRootClientWindowThenRetired` — old-root client in window, then a
  readable `root_retired` failure.
- `TestOnlineSwitchNoFailedRequests` — concurrent issuance across cut-over,
  zero failures.
- `TestAffectedCertificatesAfterRetirement` — accurate reverse-listed scope.
- `TestPerRootCRLIsolationAndStaleFallback`, `TestServerCertCoexistence`,
  `TestChainOrderAndShortestPath`, `TestObservability`,
  `TestNewRootLoadFailureKeepsOldWorking`, `TestSingleRootParity`, and the
  lifecycle/config-rejection tests.

## Integration note

The engine is exposed as an additive, opt-in package and is not wired into the
existing static `Authority.rootX509Certs` slice, so current single-root
deployments are byte-for-byte unchanged. An embedding authority constructs a
`Manager` from its parsed roots (`NewManagerFromBundles`), registers each
issuer (`RegisterIssuer`), and can then back its signing, root endpoint, CRL
endpoint, and TLS `GetCertificate` with the rotation APIs without altering any
existing request/response structure.
