package rotation

import (
	"crypto"
	"crypto/x509"
	"time"
)

// Issuer is the signing material associated with a root. A root may issue
// through one or more intermediates; the active chain is intermediates[0..n]
// terminated by the root. Signer is the private key of the issuing
// intermediate (or the root itself for a direct issuer).
type Issuer struct {
	// Signer signs leaf certificates. It corresponds to Chain[0].
	Signer crypto.Signer

	// Chain is the issuer chain ordered leaf-to-root: the issuing intermediate
	// first, further intermediates next, and the root last. Every entry is
	// non-nil and the final entry must be the root certificate.
	Chain []*x509.Certificate
}

// rootEntry is the engine's internal record for a single root. It is immutable
// once published inside a snapshot; lifecycle/window changes produce a new
// snapshot rather than mutating shared state.
type rootEntry struct {
	id        string
	fp        string
	cert      *x509.Certificate
	state     State
	notBefore time.Time
	notAfter  time.Time
	issuer    *Issuer
	issued    uint64
	ski       []byte // root SubjectKeyId, used for issuer reverse lookup
}

// inWindow reports whether t falls inside the root's trust window. A zero
// NotBefore means always-valid from the past; a zero NotAfter means no end.
func (r *rootEntry) inWindow(t time.Time) bool {
	if !r.notBefore.IsZero() && t.Before(r.notBefore) {
		return false
	}
	if !r.notAfter.IsZero() && !t.Before(r.notAfter) {
		return false
	}
	return true
}

// effectiveState folds the time window into the explicit lifecycle state.
//
//   - Before NotBefore a root cannot yet be trusted (StateNotYetValid surface).
//   - At/after NotAfter it is treated as retired even if config still says
//     trusted, because the configured window has elapsed.
//   - Otherwise the explicit lifecycle state wins.
//
// The explicit state itself never moves backwards; this function only narrows
// usability based on the clock.
func (r *rootEntry) effectiveState(t time.Time) State {
	if !r.notBefore.IsZero() && t.Before(r.notBefore) {
		// Not yet valid is a distinct, explainable condition, not "retired".
		return stateNotYetValid
	}
	if !r.notAfter.IsZero() && !t.Before(r.notAfter) {
		return StateRetired
	}
	return r.state
}

// stateNotYetValid is an internal-only sentinel returned by effectiveState. It
// is never stored and never participates in transition checks.
const stateNotYetValid State = -1

// trustedForVerify reports whether certificates anchored by this root verify at
// time t. Retired (or expired-window) roots do not verify; stopped and trusted
// roots do while inside their window.
func (r *rootEntry) trustedForVerify(t time.Time) bool {
	return r.effectiveState(t) != StateRetired && r.effectiveState(t) != stateNotYetValid
}

// canIssue reports whether this root may sign new certificates at time t. A
// root must be explicitly StateTrusted, inside its window, and have usable
// signing material.
func (r *rootEntry) canIssue(t time.Time) bool {
	if r.effectiveState(t) != StateTrusted {
		return false
	}
	return r.issuer != nil && r.issuer.Signer != nil && len(r.issuer.Chain) > 0
}

// timeLeft returns how much longer the root stays trusted relative to t. A
// negative/zero duration means the window has elapsed; a zero NotAfter yields
// a large sentinel meaning "no scheduled end".
func (r *rootEntry) timeLeft(t time.Time) time.Duration {
	if r.notAfter.IsZero() {
		return time.Duration(1<<63 - 1)
	}
	return r.notAfter.Sub(t)
}
