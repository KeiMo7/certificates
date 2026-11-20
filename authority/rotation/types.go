// Package rotation implements multi-root certificate authority coexistence and
// time-based root rotation.
//
// It lets a CA trust several root certificates at the same time, each carrying
// its own validity window (NotBefore / NotAfter) and a one-way lifecycle
// (trusted -> stopped issuing -> retired). New certificates are signed by the
// currently active issuing root, which can change automatically over time
// without restarting the process. The package also owns deterministic chain
// building, per-root certificate revocation lists, an atomic online root-set
// reload that never leaves the CA without a usable root, server certificate
// coexistence during renewal, and observability of the active window.
//
// The engine is deliberately self-contained: it depends only on the Go
// standard library and on crypto/x509 types, so it can be embedded in an
// authority without introducing an external service.
package rotation

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"time"
)

// State is the lifecycle state of a root certificate.
//
// Transitions are strictly one way and only ever move forward:
//
//	StateTrusted -> StateStopped -> StateRetired
//
// A root never goes back to a less-restrictive state. This guarantees that a
// retired root cannot silently start issuing or being trusted again because of
// a configuration reload or a clock/load-order artifact.
type State int

const (
	// StateTrusted means the root is trusted for verification and may be used
	// to issue new certificates while it is the active issuer.
	StateTrusted State = iota

	// StateStopped means the root is still trusted for verifying certificates
	// it already signed, but it must not be selected as the issuing root for
	// new certificates.
	StateStopped

	// StateRetired means the root is no longer trusted. Certificates it signed
	// can still be identified (their issuer link is retained) but chains built
	// on it fail verification with an explicit "retired" reason.
	StateRetired
)

// String returns the stable, human-readable name of a state. These names are
// part of the external root-set representation and must not change.
func (s State) String() string {
	switch s {
	case StateTrusted:
		return "trusted"
	case StateStopped:
		return "stopped"
	case StateRetired:
		return "retired"
	default:
		return "unknown"
	}
}

// canTransitionTo reports whether moving from s to next is legal. Only forward
// movement along the lifecycle is allowed; staying in place is legal (a reload
// that does not change a root's state must succeed).
func (s State) canTransitionTo(next State) bool {
	switch {
	case next == s:
		return true
	case s == StateTrusted && (next == StateStopped || next == StateRetired):
		return true
	case s == StateStopped && next == StateRetired:
		return true
	default:
		return false
	}
}

// RootConfig is the declarative description of one root in a rotation set.
//
// NotBefore and NotAfter define the window during which the root is trusted.
// Outside that window a root behaves as retired for verification, but the
// explicit lifecycle State still governs issuing and never moves backwards.
type RootConfig struct {
	// ID is the caller-chosen stable identifier for the root. When empty it is
	// derived deterministically from the certificate fingerprint. It must be
	// unique within a set.
	ID string

	// Certificate is the self-signed root certificate. Required.
	Certificate *x509.Certificate

	// State is the desired lifecycle state. Zero value StateTrusted is the
	// default for freshly added roots.
	State State

	// NotBefore is when the root starts being trusted. Zero means "already in
	// effect".
	NotBefore time.Time

	// NotAfter is when the root stops being trusted (retirement time). Zero
	// means "no scheduled end". A zero NotAfter combined with StateRetired is
	// still treated as retired.
	NotAfter time.Time
}

// Fingerprint returns the canonical identifier of a certificate's raw bytes:
// the lowercase hex SHA-256 of the DER encoding, matching step-ca's existing
// fingerprint convention.
func Fingerprint(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
