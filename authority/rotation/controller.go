package rotation

import (
	"crypto/x509"
	"time"
)

// RootBundle is the minimal input needed to add a root to a rotation set when an
// embedding authority already holds parsed certificates. It lets callers build a
// Manager without hand-writing RootConfig values.
type RootBundle struct {
	// ID is the stable root identifier; optional (fingerprint is used when empty).
	ID string
	// Certificate is the self-signed root.
	Certificate *x509.Certificate
	// NotBefore / NotAfter bound the trust window. Zero NotBefore means already
	// active; zero NotAfter means no scheduled retirement.
	NotBefore time.Time
	NotAfter  time.Time
}

// NewManagerFromBundles is a convenience constructor for authorities that start
// from a list of parsed root certificates (for example an existing single-root
// deployment). Every supplied root enters in StateTrusted; a single bundle
// yields behavior identical to a classic one-root CA.
func NewManagerFromBundles(bundles []RootBundle, opts ...Option) (*Manager, error) {
	cfgs := make([]RootConfig, 0, len(bundles))
	for _, b := range bundles {
		cfgs = append(cfgs, RootConfig{
			ID:          b.ID,
			Certificate: b.Certificate,
			State:       StateTrusted,
			NotBefore:   b.NotBefore,
			NotAfter:    b.NotAfter,
		})
	}
	return NewManager(cfgs, opts...)
}

// ConfigsFromBundles converts bundles into RootConfig values for an explicit
// Reload while preserving each root's current lifecycle state when desired.
func ConfigsFromBundles(bundles []RootBundle, states map[string]State) []RootConfig {
	out := make([]RootConfig, 0, len(bundles))
	for _, b := range bundles {
		st := StateTrusted
		if states != nil {
			if s, ok := states[b.ID]; ok {
				st = s
			}
		}
		out = append(out, RootConfig{
			ID:          b.ID,
			Certificate: b.Certificate,
			State:       st,
			NotBefore:   b.NotBefore,
			NotAfter:    b.NotAfter,
		})
	}
	return out
}

// TrustedFingerprints returns the hex SHA-256 fingerprints of roots currently
// trusted for verification (active or stopped, in-window). It is convenient for
// building client VerifyOptions.TrustedRoots and for compatibility with code that
// already keys roots by fingerprint.
func (m *Manager) TrustedFingerprints() []string {
	snap, t := m.snapshotNow()
	var out []string
	for _, e := range snap.order {
		if e.trustedForVerify(t) {
			out = append(out, e.fp)
		}
	}
	return out
}

// RootByFingerprint returns the root id for a fingerprint, or false.
func (m *Manager) RootByFingerprint(fp string) (string, bool) {
	if e, ok := m.snap.Load().byFP[fp]; ok {
		return e.id, true
	}
	return "", false
}
