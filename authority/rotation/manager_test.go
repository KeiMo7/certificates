package rotation

import (
	"testing"
	"time"
)

// mutableClock is a controllable time source whose value can be advanced.
type mutableClock struct{ t time.Time }

func (c *mutableClock) now() time.Time      { return c.t }
func (c *mutableClock) set(t time.Time)     { c.t = t }
func (c *mutableClock) add(d time.Duration) { c.t = c.t.Add(d) }

func newTwoRootManager(t *testing.T, now time.Time, oldEnd, newStart, newEnd time.Time) (*Manager, *testCA, *testCA, *mutableClock) {
	t.Helper()
	clk := &mutableClock{t: now}
	oldCA, err := newTestRootCA("Old Root")
	if err != nil {
		t.Fatalf("old CA: %v", err)
	}
	newCA, err := newTestRootCA("New Root")
	if err != nil {
		t.Fatalf("new CA: %v", err)
	}
	m, err := NewManager([]RootConfig{
		rootConfig(oldCA, "old", StateTrusted, now.Add(-time.Hour), oldEnd),
		rootConfig(newCA, "new", StateTrusted, newStart, newEnd),
	}, WithClock(clk.now))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if err := m.RegisterIssuer("old", oldCA.issuer()); err != nil {
		t.Fatalf("register old: %v", err)
	}
	if err := m.RegisterIssuer("new", newCA.issuer()); err != nil {
		t.Fatalf("register new: %v", err)
	}
	return m, oldCA, newCA, clk
}

// Spec 1 & hard-constraint 4: both roots trusted in window; verification result
// must not depend on load/configuration order.
func TestDualRootWindowBothTrusted(t *testing.T) {
	now := time.Now()
	oldEnd := now.Add(2 * time.Hour)
	newStart := now.Add(-1 * time.Hour)
	newEnd := now.Add(24 * time.Hour)

	build := func(reverse bool) (*Manager, *testCA, *testCA) {
		oldCA, _ := newTestRootCA("Old Root")
		newCA, _ := newTestRootCA("New Root")
		cfgs := []RootConfig{
			rootConfig(oldCA, "old", StateTrusted, now.Add(-time.Hour), oldEnd),
			rootConfig(newCA, "new", StateTrusted, newStart, newEnd),
		}
		if reverse {
			cfgs[0], cfgs[1] = cfgs[1], cfgs[0]
		}
		m, err := NewManager(cfgs, WithClock((&mutableClock{t: now}).now))
		if err != nil {
			t.Fatalf("NewManager: %v", err)
		}
		if err := m.RegisterIssuer("old", oldCA.issuer()); err != nil {
			t.Fatal(err)
		}
		if err := m.RegisterIssuer("new", newCA.issuer()); err != nil {
			t.Fatal(err)
		}
		return m, oldCA, newCA
	}

	for _, reverse := range []bool{false, true} {
		m, oldCA, newCA := build(reverse)
		oldLeaf, _, _ := oldCA.issueLeaf("old.example.com", now.Add(-time.Minute), now.Add(time.Hour))
		newLeaf, _, _ := newCA.issueLeaf("new.example.com", now.Add(-time.Minute), now.Add(time.Hour))

		if _, err := m.Verify(oldLeaf, VerifyOptions{}); err != nil {
			t.Fatalf("reverse=%v: old root leaf should verify in window: %v", reverse, err)
		}
		if _, err := m.Verify(newLeaf, VerifyOptions{}); err != nil {
			t.Fatalf("reverse=%v: new root leaf should verify in window: %v", reverse, err)
		}
	}
}

// Spec 2 & 8: active issuer auto-switches by time without restart, and the
// newest in-window root is selected deterministically.
func TestAutomaticIssuerCutover(t *testing.T) {
	now := time.Now()
	switchAt := now.Add(time.Hour)
	m, _, _, clk := newTwoRootManager(t, now, now.Add(3*time.Hour), switchAt, now.Add(24*time.Hour))

	active, err := m.ActiveIssuer()
	if err != nil {
		t.Fatal(err)
	}
	if active.id != "old" {
		t.Fatalf("before new root window, expected issuer old, got %s", active.id)
	}

	// Advance the clock past the new root's NotBefore.
	clk.set(switchAt.Add(time.Minute))
	active, err = m.ActiveIssuer()
	if err != nil {
		t.Fatal(err)
	}
	if active.id != "new" {
		t.Fatalf("after cutover expected issuer new, got %s", active.id)
	}
}

// Spec 4 / acceptance 2: a client holding only the old root verifies inside the
// window; once that root retires the same verification fails with an explicit
// retired reason.
func TestOldRootClientWindowThenRetired(t *testing.T) {
	now := time.Now()
	oldEnd := now.Add(2 * time.Hour)
	m, oldCA, _, clk := newTwoRootManager(t, now, oldEnd, now.Add(-time.Hour), now.Add(24*time.Hour))

	leaf, _, _ := oldCA.issueLeaf("client.example.com", now.Add(-time.Minute), now.Add(90*time.Minute))
	oldFP := Fingerprint(oldCA.root.Raw)

	// In window: client that only carries the old root still succeeds.
	if _, err := m.Verify(leaf, VerifyOptions{TrustedRoots: []string{oldFP}}); err != nil {
		t.Fatalf("old-root client should verify in window: %v", err)
	}

	// After the old root's window ends, verification must explain retirement.
	clk.set(oldEnd.Add(time.Minute))
	_, err := m.Verify(leaf, VerifyOptions{TrustedRoots: []string{oldFP}})
	if err == nil {
		t.Fatal("expected failure after retirement, got success")
	}
	re, ok := AsError(err)
	if !ok || re.Reason != ReasonRetired {
		t.Fatalf("expected ReasonRetired, got %v", err)
	}
	if re.RootID != "old" {
		t.Fatalf("error should name old root, got %q", re.RootID)
	}
}

// Hard constraint 1 & failure 2: a configuration with no issuing root is
// rejected at load time and does not replace the running set.
func TestRejectConfigWithNoIssuer(t *testing.T) {
	now := time.Now()
	ca, _ := newTestRootCA("Solo")
	cfgs := []RootConfig{rootConfig(ca, "solo", StateStopped, now.Add(-time.Hour), now.Add(time.Hour))}
	if _, err := NewManager(cfgs, WithClock((&mutableClock{t: now}).now)); err == nil {
		t.Fatal("expected error building manager with no issuing root")
	}

	// Same rule on an online reload of a healthy manager: keep serving.
	m, oldCA, newCA, _ := newTwoRootManager(t, now, now.Add(3*time.Hour), now.Add(-time.Hour), now.Add(24*time.Hour))
	bad := []RootConfig{
		rootConfig(oldCA, "old", StateRetired, now.Add(-time.Hour), now.Add(time.Hour)),
		rootConfig(newCA, "new", StateStopped, now.Add(-time.Hour), now.Add(time.Hour)),
	}
	if err := m.Reload(bad); err == nil {
		t.Fatal("reload with no issuer must be rejected")
	}
	active, err := m.ActiveIssuer()
	if err != nil {
		t.Fatalf("previous set must keep working after rejected reload: %v", err)
	}
	if active == nil {
		t.Fatal("no active issuer after rejected reload")
	}
}

// Hard constraint 3: lifecycle state never moves backwards.
func TestOneWayLifecycle(t *testing.T) {
	now := time.Now()
	m, _, _, _ := newTwoRootManager(t, now, now.Add(24*time.Hour), now.Add(-time.Hour), now.Add(48*time.Hour))

	// Cannot retire the only issuer: 'new' must still be able to issue, so
	// stopping old is fine but retiring new while old is stopped is not.
	if err := m.Transition("old", StateStopped); err != nil {
		t.Fatalf("stop old: %v", err)
	}
	// Regression attempt: old cannot go back to trusted.
	if err := m.Transition("old", StateTrusted); err == nil {
		t.Fatal("backward transition trusted<-stopped must be rejected")
	}
	// Now retire old (forward), allowed because new still issues.
	if err := m.Transition("old", StateRetired); err != nil {
		t.Fatalf("retire old: %v", err)
	}
	// Retired cannot move back to anything.
	if err := m.Transition("old", StateStopped); err == nil {
		t.Fatal("retired -> stopped must be rejected")
	}
	if err := m.Transition("old", StateTrusted); err == nil {
		t.Fatal("retired -> trusted must be rejected")
	}
	// Refuse to stop the last remaining issuer (new).
	if err := m.Transition("new", StateStopped); err == nil {
		t.Fatal("stopping the only issuer must be rejected")
	}
}

// Failure 2: insufficient overlap / a trust gap is rejected at load.
func TestRejectTrustGap(t *testing.T) {
	now := time.Now()
	oldCA, _ := newTestRootCA("Old")
	newCA, _ := newTestRootCA("New")
	cfgs := []RootConfig{
		rootConfig(oldCA, "old", StateTrusted, now.Add(-2*time.Hour), now.Add(time.Hour)),
		rootConfig(newCA, "new", StateTrusted, now.Add(2*time.Hour), now.Add(24*time.Hour)),
	}
	_, err := NewManager(cfgs, WithClock((&mutableClock{t: now}).now), WithMinOverlap(time.Minute))
	if err == nil {
		t.Fatal("expected trust-gap rejection")
	}
	re, ok := AsError(err)
	if !ok || re.Reason != ReasonConfig {
		t.Fatalf("expected ReasonConfig, got %v", err)
	}
}

// Spec 7: external root set distinguishes active issuer / trusted-not-issuing /
// retired.
func TestRootSetThreeStates(t *testing.T) {
	now := time.Now()
	m, oldCA, newCA, _ := newTwoRootManager(t, now, now.Add(24*time.Hour), now.Add(-time.Hour), now.Add(48*time.Hour))
	if err := m.Transition("old", StateStopped); err != nil {
		t.Fatal(err)
	}

	set := m.Snapshot()
	if set.ActiveIssuerID != "new" {
		t.Fatalf("expected new active issuer, got %q", set.ActiveIssuerID)
	}
	status := map[string]RootStatus{}
	for _, r := range set.Roots {
		status[r.ID] = r.Status
	}
	if status["new"] != StatusActiveIssuer {
		t.Fatalf("new should be active issuer, got %s", status["new"])
	}
	if status["old"] != StatusTrusted {
		t.Fatalf("old stopped should be trusted-not-issuing, got %s", status["old"])
	}

	// Retire a fresh third root to see the retired state.
	third, _ := newTestRootCA("Third")
	err := m.Reload([]RootConfig{
		rootConfig(oldCA, "old", StateStopped, now.Add(-time.Hour), now.Add(24*time.Hour)),
		rootConfig(newCA, "new", StateTrusted, now.Add(-time.Hour), now.Add(48*time.Hour)),
		rootConfig(third, "third", StateRetired, now.Add(-time.Hour), now.Add(time.Hour)),
	})
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	set = m.Snapshot()
	for _, r := range set.Roots {
		if r.ID == "third" && r.Status != StatusRetired {
			t.Fatalf("third should be retired, got %s", r.Status)
		}
	}
}
