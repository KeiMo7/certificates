package rotation

import (
	"crypto/x509"
)

// Chain is a fully ordered certificate path: leaf first, zero or more
// intermediates, and the anchoring root last.
type Chain struct {
	// Certs is leaf -> ... -> root.
	Certs []*x509.Certificate

	// RootID is the id of the root anchoring this chain.
	RootID string

	// Retired is true when the anchoring root is past its window or explicitly
	// retired. Such a chain is returned for identification/listing but will fail
	// Verify with a ReasonRetired error.
	Retired bool
}

// BuildChain assembles the best chain for the given leaf, using the roots and
// their registered issuer chains in the current snapshot.
//
// Selection rules, in order:
//  1. Only chains whose issuer link actually reaches a known root are
//     considered (the leaf -> root relationship is resolved structurally, not
//     by fingerprint string matching).
//  2. Chains anchored by a non-retired, in-window root are always preferred
//     over retired anchors.
//  3. Among equally valid anchors, the shortest chain wins.
//  4. Ties are broken deterministically by root id so the result never depends
//     on load order.
func (m *Manager) BuildChain(leaf *x509.Certificate) (*Chain, error) {
	if leaf == nil {
		return nil, newError(ReasonBrokenChain, "", "leaf certificate cannot be nil")
	}
	snap, t := m.snapshotNow()

	anchorID, err := snap.rootIDByAKI(leaf)
	if err != nil {
		return nil, err
	}
	entry, ok := snap.byID[anchorID]
	if !ok {
		return nil, newError(ReasonNoRoot, "", "resolved root id %q is not present in the root set", anchorID)
	}
	if entry.issuer == nil || len(entry.issuer.Chain) == 0 {
		return nil, newError(ReasonBrokenChain, entry.id,
			"root matches but it has no registered issuer chain; missing intermediate link for leaf issued by %q",
			leaf.Issuer.CommonName)
	}

	// leaf, then the issuer chain (intermediate(s), root).
	certs := make([]*x509.Certificate, 0, len(entry.issuer.Chain)+1)
	certs = append(certs, leaf)
	certs = append(certs, entry.issuer.Chain...)

	st := entry.effectiveState(t)
	return &Chain{
		Certs:   certs,
		RootID:  entry.id,
		Retired: st == StateRetired || st == stateNotYetValid,
	}, nil
}

// VerifyOptions carries the trusted material a relying party presents. When
// TrustedRoots is non-nil it models a client that only holds a subset (e.g. an
// old root); verification succeeds only if a chain anchors on one of them.
type VerifyOptions struct {
	// TrustedRoots, when non-empty, restricts acceptable anchors to these root
	// fingerprints (hex SHA-256). An empty slice means "trust every root the
	// manager currently considers trusted".
	TrustedRoots []string

	// KeyUsages mirrors x509.VerifyOptions.KeyUsages; defaults to server auth.
	KeyUsages []x509.ExtKeyUsage
}

// Verify builds a chain for leaf and validates it. It returns an explainable
// *Error distinguishing: client holds only an old/retired root (ReasonRetired),
// the root window has not started (ReasonNotYetValid), no known root anchors
// the leaf (ReasonNoRoot), or a missing intermediate (ReasonBrokenChain).
//
// When opts.TrustedRoots is set it represents the roots the relying party
// trusts; during a rotation window a client holding only the old root still
// verifies because the old root remains trusted inside its window.
func (m *Manager) Verify(leaf *x509.Certificate, opts VerifyOptions) (*Chain, error) {
	chain, err := m.BuildChain(leaf)
	if err != nil {
		return nil, err
	}
	snap, t := m.snapshotNow()
	entry := snap.byID[chain.RootID]

	// Restrict to the roots the relying party actually holds.
	if len(opts.TrustedRoots) > 0 {
		held := false
		for _, fp := range opts.TrustedRoots {
			if fp == entry.fp {
				held = true
				break
			}
		}
		if !held {
			return nil, newError(ReasonNoRoot, entry.id,
				"relying party does not hold the root %q that anchors this certificate", entry.id)
		}
	}

	switch entry.effectiveState(t) {
	case stateNotYetValid:
		return nil, newError(ReasonNotYetValid, entry.id,
			"root %q trust window starts at %s (now %s)", entry.id,
			entry.notBefore.UTC().Format("2006-01-02T15:04:05Z"),
			t.UTC().Format("2006-01-02T15:04:05Z"))
	case StateRetired:
		return nil, newError(ReasonRetired, entry.id,
			"root %q was retired at %s; certificates on this chain are no longer trusted",
			entry.id, retirementTime(entry))
	default:
		// Root is trusted and in-window. Run a real x509 path verification
		// against a pool containing exactly this root and the intermediates.
		if err := x509Verify(chain, opts); err != nil {
			return nil, newError(ReasonBrokenChain, entry.id, "path verification failed: %v", err)
		}
	}
	return chain, nil
}

// x509Verify performs standard library certificate verification over the
// assembled chain, trusting only its root.
func x509Verify(chain *Chain, opts VerifyOptions) error {
	roots := x509.NewCertPool()
	roots.AddCert(chain.Certs[len(chain.Certs)-1])

	intermediates := x509.NewCertPool()
	for _, c := range chain.Certs[1 : len(chain.Certs)-1] {
		intermediates.AddCert(c)
	}

	ku := opts.KeyUsages
	if ku == nil {
		ku = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	_, err := chain.Certs[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     ku,
	})
	return err
}

func retirementTime(e *rootEntry) string {
	if e.notAfter.IsZero() {
		return "an unspecified time"
	}
	return e.notAfter.UTC().Format("2006-01-02T15:04:05Z")
}
