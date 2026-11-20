package rotation

import (
	"crypto/x509"
	"math/big"
	"sync"
	"time"
)

// RevokedEntry is one revoked serial for a particular root.
type RevokedEntry struct {
	// SerialNumber is the revoked certificate's serial, as the raw DER integer
	// bytes (matches x509.RevocationListEntry.SerialNumber).
	SerialNumber []byte
	// RevokedAt is when revocation took effect.
	RevokedAt time.Time
	// Reason is the CRL reason code (e.g. x509.ReasonKeyCompromise).
	Reason int
}

// CRLGenerator produces the DER-encoded CRL for a single root. It is supplied by
// the embedding authority (which owns the signer and the revocation store). The
// engine never shares one root's list with another.
type CRLGenerator func(rootID string, issuer *Issuer, revoked []RevokedEntry) ([]byte, error)

// crlHolder keeps the last successfully generated CRL for one root. On
// generation failure the previous bytes continue to be served and Stale is set,
// so a transient failure never produces an empty list that silently
// resuscitates revoked certificates.
type crlHolder struct {
	mu      sync.RWMutex
	der     []byte
	number  int64
	stale   bool
	updated time.Time
	revoked []RevokedEntry
}

// CRLView is the externally visible state of a root's CRL.
type CRLView struct {
	RootID    string
	Available bool
	Stale     bool
	Number    int64
	Updated   time.Time
	// RevokedCount is the number of entries the list reflects.
	RevokedCount int
}

// SetRevoked replaces the revoked set for a single root and regenerates its CRL
// via gen. Each root's list is fully independent: updating root A never touches
// root B's holder or bytes. If generation fails the previous good CRL is
// retained and flagged stale, and a ReasonCRL error is returned for alerting.
func (m *Manager) SetRevoked(rootID string, revoked []RevokedEntry, gen CRLGenerator) error {
	snap := m.snap.Load()
	entry, ok := snap.byID[rootID]
	if !ok {
		return newError(ReasonConfig, rootID, "cannot update CRL: unknown root id")
	}
	if entry.issuer == nil {
		return newError(ReasonConfig, rootID, "cannot generate CRL: root has no registered issuer")
	}

	m.crlMu.Lock()
	h := m.crls[rootID]
	if h == nil {
		h = &crlHolder{}
		m.crls[rootID] = h
	}
	m.crlMu.Unlock()

	der, err := gen(rootID, entry.issuer, revoked)
	if err != nil {
		// Degradation path: keep last good list, mark stale.
		h.mu.Lock()
		h.stale = true
		h.mu.Unlock()
		return (&Error{
			Reason:  ReasonCRL,
			RootID:  rootID,
			Stale:   true,
			Message: "CRL generation failed; retained last usable list and marked it stale: " + err.Error(),
		})
	}

	h.mu.Lock()
	h.der = der
	h.number++
	h.stale = false
	h.updated = m.now()
	h.revoked = append([]RevokedEntry(nil), revoked...)
	h.mu.Unlock()
	return nil
}

// GetCRL returns the current DER CRL for a root and whether it is stale. When no
// list has ever been generated it returns a typed ReasonCRL error.
func (m *Manager) GetCRL(rootID string) (der []byte, stale bool, err error) {
	if _, ok := m.snap.Load().byID[rootID]; !ok {
		return nil, false, newError(ReasonConfig, rootID, "unknown root id")
	}
	m.crlMu.Lock()
	h := m.crls[rootID]
	m.crlMu.Unlock()
	if h == nil {
		return nil, false, newError(ReasonCRL, rootID, "no CRL has been generated for this root yet")
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.der == nil {
		return nil, false, newError(ReasonCRL, rootID, "no usable CRL for this root")
	}
	return append([]byte(nil), h.der...), h.stale, nil
}

// CRLStatus returns observability data for every root's independent CRL.
func (m *Manager) CRLStatus() []CRLView {
	snap := m.snap.Load()
	out := make([]CRLView, 0, len(snap.order))
	for _, e := range snap.order {
		view := CRLView{RootID: e.id}
		m.crlMu.Lock()
		h := m.crls[e.id]
		m.crlMu.Unlock()
		if h != nil {
			h.mu.RLock()
			view.Available = h.der != nil
			view.Stale = h.stale
			view.Number = h.number
			view.Updated = h.updated
			view.RevokedCount = len(h.revoked)
			h.mu.RUnlock()
		}
		out = append(out, view)
	}
	return out
}

// RevokedForRoot returns the revoked entries currently recorded for a root. It
// exists so callers can rebuild a list without sharing holders across roots.
func (m *Manager) RevokedForRoot(rootID string) ([]RevokedEntry, error) {
	m.crlMu.Lock()
	h := m.crls[rootID]
	m.crlMu.Unlock()
	if h == nil {
		return nil, nil
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	return append([]RevokedEntry(nil), h.revoked...), nil
}

// StandardGenerator builds a CRLGenerator from x509.RevocationList templates
// using the root's own intermediate signer, via x509.CreateRevocationList. It is
// a convenience for authorities that do not already have CRL machinery.
func StandardGenerator(tpl *x509.RevocationList) CRLGenerator {
	return func(_ string, issuer *Issuer, revoked []RevokedEntry) ([]byte, error) {
		entries := make([]x509.RevocationListEntry, 0, len(revoked))
		for _, r := range revoked {
			entries = append(entries, x509.RevocationListEntry{
				SerialNumber:   new(big.Int).SetBytes(r.SerialNumber),
				RevocationTime: r.RevokedAt,
				ReasonCode:     r.Reason,
			})
		}
		t := *tpl
		t.RevokedCertificateEntries = entries
		parent := issuer.Chain[0]
		return x509.CreateRevocationList(nil, &t, parent, issuer.Signer)
	}
}
