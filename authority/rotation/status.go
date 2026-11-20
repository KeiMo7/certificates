package rotation

import (
	"crypto/x509"
	"time"
)

// RootStatus is the externally reported classification of a root. It is the
// three-state view the root endpoint must distinguish.
type RootStatus string

const (
	// StatusActiveIssuer is the root currently signing new certificates.
	StatusActiveIssuer RootStatus = "active_issuer"
	// StatusTrusted is trusted for verification but has stopped issuing.
	StatusTrusted RootStatus = "trusted_not_issuing"
	// StatusRetired is no longer trusted (retired or outside its window).
	StatusRetired RootStatus = "retired"
)

// RootView is the serializable, parseable entry in the public root set. The
// format is additive over a bare certificate list: existing clients that only
// read the PEM/certificate bytes continue to work, while new consumers can read
// the status and window fields.
type RootView struct {
	ID          string
	Fingerprint string
	Status      RootStatus
	// Lifecycle is the explicit configured state (trusted/stopped/retired),
	// independent of the time-derived effective status.
	Lifecycle   string
	Certificate *x509.Certificate
	NotBefore   time.Time
	NotAfter    time.Time
	// Remaining is how long the root stays trusted from now; negative means the
	// window has elapsed. Zero NotAfter is reported as a very large duration.
	Remaining time.Duration
	// Issued is the count of certificates signed under this root since the
	// manager started.
	Issued uint64
}

// RootSet is the full public view used by the root endpoint and metrics.
type RootSet struct {
	// ActiveIssuerID is the root that would sign a new certificate right now.
	ActiveIssuerID string
	// WindowStart / WindowEnd describe the overall envelope of currently trusted
	// roots, i.e. the active rotation window.
	WindowStart time.Time
	WindowEnd   time.Time
	// Remaining is time until the earliest in-window trusted root retires.
	Remaining time.Duration
	Roots     []RootView
}

// Snapshot returns the public, time-evaluated root set with explicit statuses.
func (m *Manager) Snapshot() *RootSet {
	snap, t := m.snapshotNow()
	out := &RootSet{Remaining: 1<<63 - 1}

	active, _ := m.ActiveIssuer()
	if active != nil {
		out.ActiveIssuerID = active.id
	}

	for _, e := range snap.order {
		view := RootView{
			ID:          e.id,
			Fingerprint: e.fp,
			Lifecycle:   e.state.String(),
			Certificate: e.cert,
			NotBefore:   e.notBefore,
			NotAfter:    e.notAfter,
			Remaining:   e.timeLeft(t),
			Issued:      e.issued,
		}
		switch st := e.effectiveState(t); {
		case active != nil && e.id == active.id:
			view.Status = StatusActiveIssuer
		case st == StateRetired || st == stateNotYetValid:
			view.Status = StatusRetired
		case e.state == StateStopped:
			view.Status = StatusTrusted
		default:
			// In-window trusted root that is not the currently active issuer.
			view.Status = StatusTrusted
		}
		out.Roots = append(out.Roots, view)

		// Aggregate the envelope over in-window trusted/stopped roots.
		if e.trustedForVerify(t) {
			if out.WindowStart.IsZero() || (!e.notBefore.IsZero() && e.notBefore.Before(out.WindowStart)) {
				out.WindowStart = e.notBefore
			}
			if e.notAfter.After(out.WindowEnd) {
				out.WindowEnd = e.notAfter
			}
			if tl := e.timeLeft(t); tl < out.Remaining {
				out.Remaining = tl
			}
		}
	}
	return out
}

// Transition moves a root to a new lifecycle state. The move must be legal per
// the one-way state machine; illegal/backward transitions are rejected without
// changing state. This is the supported online way to stop issuing on, and then
// retire, a root.
func (m *Manager) Transition(rootID string, next State) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	snap := m.snap.Load()
	cur, ok := snap.byID[rootID]
	if !ok {
		return newError(ReasonConfig, rootID, "unknown root id")
	}
	if !cur.state.canTransitionTo(next) {
		return newError(ReasonConfig, rootID,
			"illegal lifecycle transition %s -> %s; only trusted -> stopped -> retired is allowed",
			cur.state, next)
	}
	if cur.state == next {
		return nil
	}
	// Hard constraint: retiring/stopping the only issuer must not leave the CA
	// unable to issue. Check whether another root can still issue.
	if next != StateTrusted {
		hasOther := false
		t := m.now()
		for _, e := range snap.order {
			if e.id == rootID {
				continue
			}
			if e.canIssue(t) {
				hasOther = true
				break
			}
		}
		if !hasOther {
			return newError(ReasonNoIssuer, rootID,
				"transition to %s rejected: no other root can issue, refusing to leave the CA without an issuing root", next)
		}
	}

	ns := snap.clone()
	ne := *cur
	ne.state = next
	ns.byID[rootID] = &ne
	ns.reindex()
	m.snap.Store(ns)
	return nil
}

// AffectedResult lists certificates anchored by a given root. The engine itself
// only stores the authoritative leaf index for certs it signed; the optional
// resolver lets an embedding authority enrich the result with certificates held
// in its database (including certs issued before this feature existed).
type AffectedResult struct {
	RootID        string
	Retired       bool
	SerialNumbers [][]byte
}

// CertificateResolver returns serials (raw DER) of certificates whose issuer
// link resolves to rootID. Implementations typically query the CA database.
type CertificateResolver func(rootID string) ([][]byte, error)

// AffectedCertificates returns the still-relevant certificate scope of a root:
// certificates that chain to it and have not expired. It merges the engine's
// authoritative issuance index with the optional resolver and de-duplicates by
// serial, so the reported range is accurate rather than fingerprint-guessed.
func (m *Manager) AffectedCertificates(rootID string, resolver CertificateResolver) (*AffectedResult, error) {
	snap, t := m.snapshotNow()
	entry, ok := snap.byID[rootID]
	if !ok {
		return nil, newError(ReasonConfig, rootID, "unknown root id")
	}

	seen := map[string]bool{}
	res := &AffectedResult{
		RootID:  rootID,
		Retired: entry.effectiveState(t) == StateRetired || entry.effectiveState(t) == stateNotYetValid,
	}

	add := func(serial []byte) {
		key := string(serial)
		if seen[key] {
			return
		}
		seen[key] = true
		res.SerialNumbers = append(res.SerialNumbers, append([]byte(nil), serial...))
	}

	if m.leaves != nil {
		for serial, id := range m.leaves.bySerial {
			if id == rootID {
				add([]byte(serial))
			}
		}
	}
	if resolver != nil {
		serials, err := resolver(rootID)
		if err != nil {
			return nil, newError(ReasonConfig, rootID, "resolver failed: %v", err)
		}
		for _, s := range serials {
			add(s)
		}
	}
	return res, nil
}
