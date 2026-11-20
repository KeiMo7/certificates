package rotation

import (
	"sync"
	"testing"
	"time"
)

// Acceptance 3: switching the active issuer online must not cause any failed
// signing/verification request. We run issuance continuously in goroutines while
// advancing the clock through the cut-over, and assert every produced chain
// verifies on its anchoring root.
func TestOnlineSwitchNoFailedRequests(t *testing.T) {
	now := time.Now()
	switchAt := now.Add(2 * time.Second)
	m, _, _, clk := newTwoRootManager(t, now, now.Add(time.Hour), switchAt, now.Add(24*time.Hour))

	var wg sync.WaitGroup
	var failures int
	var mu sync.Mutex
	stop := make(chan struct{})

	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				key := mustLeafKey(t)
				res, err := m.Sign(SignRequest{
					Template:  leafTemplate("svc.example"),
					PublicKey: &key.PublicKey,
				})
				if err != nil {
					mu.Lock()
					failures++
					mu.Unlock()
					return
				}
				if _, err := m.Verify(res.Leaf, VerifyOptions{}); err != nil {
					mu.Lock()
					failures++
					mu.Unlock()
					return
				}
			}
		}()
	}

	// Move through the cut-over while issuance is in flight.
	for k := 0; k < 5; k++ {
		clk.set(switchAt.Add(time.Duration(k) * 200 * time.Millisecond))
		time.Sleep(20 * time.Millisecond)
	}
	close(stop)
	wg.Wait()

	if failures != 0 {
		t.Fatalf("had %d failures during online issuer switch", failures)
	}
	// After cut-over the new root must be the issuer.
	active, err := m.ActiveIssuer()
	if err != nil {
		t.Fatal(err)
	}
	if active.id != "new" {
		t.Fatalf("expected new issuer after switch, got %s", active.id)
	}
}

// Acceptance 4: after a root retires, reverse-listing the affected certificate
// scope must be accurate and must not rely on fingerprint string matching.
func TestAffectedCertificatesAfterRetirement(t *testing.T) {
	now := time.Now()
	m, oldCA, _, _ := newTwoRootManager(t, now, now.Add(24*time.Hour), now.Add(-time.Hour), now.Add(48*time.Hour))

	var oldSerials, newSerials [][]byte
	for i := 0; i < 3; i++ {
		key := mustLeafKey(t)
		res, err := m.Sign(SignRequest{Template: leafTemplate("old-svc"), PublicKey: &key.PublicKey})
		if err != nil {
			t.Fatal(err)
		}
		if res.RootID != "old" {
			t.Fatalf("expected old root issuance, got %s", res.RootID)
		}
		oldSerials = append(oldSerials, res.Leaf.SerialNumber.Bytes())
	}

	// Force cut-over to the new root and sign more.
	if err := m.Transition("old", StateStopped); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		key := mustLeafKey(t)
		res, err := m.Sign(SignRequest{Template: leafTemplate("new-svc"), PublicKey: &key.PublicKey})
		if err != nil {
			t.Fatal(err)
		}
		if res.RootID != "new" {
			t.Fatalf("expected new root issuance, got %s", res.RootID)
		}
		newSerials = append(newSerials, res.Leaf.SerialNumber.Bytes())
	}

	// Reverse lookup for a leaf independently issued by the old CA resolves to
	// the old root through the structural AKI link.
	indie, _, _ := oldCA.issueLeaf("indie.example", now.Add(-time.Minute), now.Add(time.Hour))
	id, err := m.RootForCertificate(indie)
	if err != nil {
		t.Fatalf("reverse lookup via AKI: %v", err)
	}
	if id != "old" {
		t.Fatalf("expected reverse lookup to resolve old, got %s", id)
	}
	// A leaf from a wholly unknown CA must produce an explainable error.
	unknown, _ := newTestRootCA("Unknown")
	uLeaf, _, _ := unknown.issueLeaf("x.example", now.Add(-time.Minute), now.Add(time.Hour))
	if _, err := m.RootForCertificate(uLeaf); err == nil {
		t.Fatal("expected error for certificate from unknown root")
	}

	// Retire the old root and list its affected scope, merging an external
	// resolver that contributes one additional stored serial.
	if err := m.Transition("old", StateRetired); err != nil {
		t.Fatal(err)
	}
	external := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	res, err := m.AffectedCertificates("old", func(rootID string) ([][]byte, error) {
		if rootID != "old" {
			t.Fatalf("resolver invoked for wrong root %s", rootID)
		}
		return [][]byte{external}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Retired {
		t.Fatal("affected result should mark root retired")
	}
	// 3 engine-indexed + 1 resolver, de-duplicated.
	if len(res.SerialNumbers) != 4 {
		t.Fatalf("expected 4 affected serials (3+1), got %d", len(res.SerialNumbers))
	}
	for _, s := range newSerials {
		for _, got := range res.SerialNumbers {
			if string(got) == string(s) {
				t.Fatal("new-root certificate leaked into old root affected scope")
			}
		}
	}
	// Sanity: new root's own scope is independent.
	newRes, err := m.AffectedCertificates("new", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(newRes.SerialNumbers) != 2 {
		t.Fatalf("expected 2 new-root serials, got %d", len(newRes.SerialNumbers))
	}
}

// Spec 9: each root has an independent CRL; a generation failure keeps the last
// good list and marks it stale rather than overwriting it.
func TestPerRootCRLIsolationAndStaleFallback(t *testing.T) {
	now := time.Now()
	m, _, _, _ := newTwoRootManager(t, now, now.Add(24*time.Hour), now.Add(-time.Hour), now.Add(48*time.Hour))

	genOK := func(_ string, _ *Issuer, revoked []RevokedEntry) ([]byte, error) {
		return []byte("crl-bytes-" + itoa(len(revoked))), nil
	}
	if err := m.SetRevoked("old", []RevokedEntry{{SerialNumber: []byte{1}, RevokedAt: now, Reason: 1}}, genOK); err != nil {
		t.Fatal(err)
	}
	if err := m.SetRevoked("new", []RevokedEntry{{SerialNumber: []byte{2}, RevokedAt: now, Reason: 1}}, genOK); err != nil {
		t.Fatal(err)
	}

	oldDER, stale, err := m.GetCRL("old")
	if err != nil || stale || string(oldDER) != "crl-bytes-1" {
		t.Fatalf("old CRL mismatch: der=%q stale=%v err=%v", oldDER, stale, err)
	}

	// A failing regeneration for old must retain its previous bytes, flag stale,
	// and not touch new.
	genFail := func(string, *Issuer, []RevokedEntry) ([]byte, error) {
		return nil, errBoom
	}
	err = m.SetRevoked("old", []RevokedEntry{{SerialNumber: []byte{9}}}, genFail)
	if err == nil {
		t.Fatal("expected CRL generation error")
	}
	re, ok := AsError(err)
	if !ok || re.Reason != ReasonCRL || !re.Stale {
		t.Fatalf("expected stale ReasonCRL error, got %v", err)
	}
	oldDER, stale, err = m.GetCRL("old")
	if err != nil || !stale || string(oldDER) != "crl-bytes-1" {
		t.Fatalf("old CRL should retain last good bytes and be stale: der=%q stale=%v err=%v", oldDER, stale, err)
	}
	newDER, newStale, _ := m.GetCRL("new")
	if newStale || string(newDER) != "crl-bytes-1" {
		t.Fatalf("new root CRL must be unaffected: der=%q stale=%v", newDER, newStale)
	}

	// Recovery: a later successful generation clears stale.
	if err := m.SetRevoked("old", []RevokedEntry{{SerialNumber: []byte{1}}, {SerialNumber: []byte{3}}}, genOK); err != nil {
		t.Fatal(err)
	}
	_, stale, _ = m.GetCRL("old")
	if stale {
		t.Fatal("stale flag should clear after successful regeneration")
	}
}

// Spec 10: observability reports the active window, remaining time and per-root
// issued counts.
func TestObservability(t *testing.T) {
	now := time.Now()
	m, _, _, _ := newTwoRootManager(t, now, now.Add(2*time.Hour), now.Add(-time.Hour), now.Add(24*time.Hour))

	for i := 0; i < 2; i++ {
		key := mustLeafKey(t)
		if _, err := m.Sign(SignRequest{Template: leafTemplate("obs"), PublicKey: &key.PublicKey}); err != nil {
			t.Fatal(err)
		}
	}
	set := m.Snapshot()
	if set.ActiveIssuerID != "old" {
		t.Fatalf("unexpected active issuer %s", set.ActiveIssuerID)
	}
	if set.WindowEnd.IsZero() {
		t.Fatal("window end should be populated")
	}
	var oldView *RootView
	for i := range set.Roots {
		if set.Roots[i].ID == "old" {
			oldView = &set.Roots[i]
		}
	}
	if oldView == nil || oldView.Issued != 2 {
		t.Fatalf("expected old root issued count 2, got %+v", oldView)
	}
	if oldView.Remaining <= 0 {
		t.Fatal("remaining time should be positive in window")
	}

	// CRL status is part of observability and stays per-root.
	status := m.CRLStatus()
	if len(status) != 2 {
		t.Fatalf("expected CRL status for 2 roots, got %d", len(status))
	}
}

// Spec 6: during a service-cert renewal both generations coexist and both
// anchor on trusted roots; the previous one remains available until it expires.
func TestServerCertCoexistence(t *testing.T) {
	now := time.Now()
	m, oldCA, newCA, _ := newTwoRootManager(t, now, now.Add(24*time.Hour), now.Add(-time.Hour), now.Add(48*time.Hour))

	oldLeaf, oldKey, _ := oldCA.issueLeaf("server.example", now.Add(-time.Minute), now.Add(time.Hour))
	ring, err := NewServerCertRing(serverCertFrom(oldLeaf, oldKey, oldCA, "old"))
	if err != nil {
		t.Fatal(err)
	}
	if got := ring.FallbackCertificate(); got != nil {
		t.Fatal("fresh ring should have no fallback")
	}

	newLeaf, newKey, _ := newCA.issueLeaf("server.example", now.Add(-time.Minute), now.Add(2*time.Hour))
	if err := ring.Renew(serverCertFrom(newLeaf, newKey, newCA, "new")); err != nil {
		t.Fatal(err)
	}

	all := ring.All()
	if len(all) != 2 {
		t.Fatalf("expected current + previous coexisting, got %d", len(all))
	}
	// Both anchor on roots currently trusted by the manager.
	for _, sc := range all {
		if _, err := m.Verify(sc.Certificate, VerifyOptions{}); err != nil {
			t.Fatalf("coexistent server cert for root %s failed verify: %v", sc.RootID, err)
		}
	}
	if ring.Current().RootID != "new" || ring.Previous().RootID != "old" {
		t.Fatalf("unexpected ring current/previous: %s / %v", ring.Current().RootID, ring.Previous())
	}
}

// Spec 3: chain building orders leaf -> intermediate -> root and prefers the
// shortest non-retired path.
func TestChainOrderAndShortestPath(t *testing.T) {
	now := time.Now()
	m, oldCA, _, _ := newTwoRootManager(t, now, now.Add(24*time.Hour), now.Add(-time.Hour), now.Add(48*time.Hour))
	leaf, _, _ := oldCA.issueLeaf("chain.example", now.Add(-time.Minute), now.Add(time.Hour))

	chain, err := m.BuildChain(leaf)
	if err != nil {
		t.Fatal(err)
	}
	if chain.RootID != "old" {
		t.Fatalf("expected old anchor, got %s", chain.RootID)
	}
	if len(chain.Certs) != 3 {
		t.Fatalf("expected leaf, intermediate, root (3), got %d", len(chain.Certs))
	}
	if chain.Certs[0].Subject.CommonName != "chain.example" ||
		chain.Certs[len(chain.Certs)-1].Subject.CommonName != "Old Root" {
		t.Fatalf("chain ordering wrong: %s ... %s", chain.Certs[0].Subject.CommonName, chain.Certs[len(chain.Certs)-1].Subject.CommonName)
	}
	if chain.Retired {
		t.Fatal("in-window chain must not be marked retired")
	}

	// Missing intermediate link yields an explainable broken-chain error naming
	// the root that matched but lacks a registered issuer.
	other, _ := newTestRootCA("Orphan")
	m2, err := NewManager([]RootConfig{
		rootConfig(oldCA, "old", StateTrusted, now.Add(-time.Hour), now.Add(24*time.Hour)),
		rootConfig(other, "orphan", StateTrusted, now.Add(-time.Hour), now.Add(24*time.Hour)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := m2.RegisterIssuer("old", oldCA.issuer()); err != nil {
		t.Fatal(err)
	}
	// Two explainable failure modes:
	// 1) Root known by SKI but has no registered issuer chain -> broken chain.
	orphanLeaf, _, _ := other.issueLeafFromRoot("orphan.example", now.Add(-time.Minute), now.Add(time.Hour))
	_, err = m2.BuildChain(orphanLeaf)
	if err == nil {
		t.Fatal("expected broken-chain error for root without registered issuer")
	}
	if re, ok := AsError(err); !ok || re.Reason != ReasonBrokenChain {
		t.Fatalf("expected ReasonBrokenChain, got %v", err)
	}

	// 2) Cert from a wholly unknown CA -> untrusted root naming the missing SKI.
	unknownLeaf, _, _ := other.issueLeaf("unknown.example", now.Add(-time.Minute), now.Add(time.Hour))
	_, err = m2.BuildChain(unknownLeaf)
	if err == nil {
		t.Fatal("expected error for certificate from unknown root")
	}
	if re, ok := AsError(err); !ok || re.Reason != ReasonNoRoot || re.MissingID == "" {
		t.Fatalf("expected ReasonNoRoot with missing id, got %v", err)
	}
}

// Failure 1: when a new root fails to load, the old root keeps serving and the
// running set is untouched.
func TestNewRootLoadFailureKeepsOldWorking(t *testing.T) {
	now := time.Now()
	m, oldCA, newCA, _ := newTwoRootManager(t, now, now.Add(24*time.Hour), now.Add(-time.Hour), now.Add(48*time.Hour))

	// A reload that illegally regresses a state must be rejected.
	bad := []RootConfig{
		rootConfig(oldCA, "old", StateTrusted, now.Add(-time.Hour), now.Add(24*time.Hour)),
		// new was trusted; asking it to be removed is rejected (no silent drop).
	}
	if err := m.Reload(bad); err == nil {
		t.Fatal("reload dropping a root must be rejected")
	}

	// A reload referencing a nil certificate is also rejected.
	if err := m.Reload([]RootConfig{
		rootConfig(oldCA, "old", StateTrusted, now.Add(-time.Hour), now.Add(24*time.Hour)),
		rootConfig(newCA, "new", StateTrusted, now.Add(-time.Hour), now.Add(48*time.Hour)),
		{ID: "broken", State: StateTrusted, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)},
	}); err == nil {
		t.Fatal("reload with nil certificate must be rejected")
	}

	// The original two-root set keeps issuing and verifying.
	key := mustLeafKey(t)
	res, err := m.Sign(SignRequest{Template: leafTemplate("still-working"), PublicKey: &key.PublicKey})
	if err != nil {
		t.Fatalf("old root must keep working after failed loads: %v", err)
	}
	if _, err := m.Verify(res.Leaf, VerifyOptions{}); err != nil {
		t.Fatalf("verification after failed load: %v", err)
	}
}

// Spec 1 / non-breaking: a single-root configuration works through the same
// engine surface, exercising the single-cert deployment path.
func TestSingleRootParity(t *testing.T) {
	now := time.Now()
	ca, _ := newTestRootCA("Solo Root")
	m, err := NewManager([]RootConfig{
		rootConfig(ca, "solo", StateTrusted, now.Add(-time.Hour), now.Add(24*time.Hour)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.RegisterIssuer("solo", ca.issuer()); err != nil {
		t.Fatal(err)
	}
	set := m.Snapshot()
	if len(set.Roots) != 1 || set.ActiveIssuerID != "solo" {
		t.Fatalf("single root view wrong: %+v", set)
	}
	key := mustLeafKey(t)
	res, err := m.Sign(SignRequest{Template: leafTemplate("solo-svc"), PublicKey: &key.PublicKey})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Chain) != 3 {
		t.Fatalf("expected leaf/inter/root chain, got %d", len(res.Chain))
	}
	if _, err := m.Verify(res.Leaf, VerifyOptions{}); err != nil {
		t.Fatalf("single-root verify failed: %v", err)
	}
}
