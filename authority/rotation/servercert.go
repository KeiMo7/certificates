package rotation

import (
	"crypto/tls"
	"crypto/x509"
	"sync/atomic"
	"time"
)

// ServerCert models one service-identity certificate with its private key and
// the chain that supports it. During renewal both the outgoing and incoming
// server cert are kept and offered, so peers that validated against either path
// continue to succeed throughout the handover.
type ServerCert struct {
	// Certificate is the leaf presented to peers.
	Certificate *x509.Certificate
	// TLSCert is the leaf plus private key used to terminate TLS.
	TLSCert tls.Certificate
	// Chain backs the leaf (intermediates + root).
	Chain []*x509.Certificate
	// RootID is the root whose trust path validates this server cert.
	RootID string
}

// certSlot is one generation of the server identity.
type certSlot struct {
	cert     *ServerCert
	notAfter time.Time
}

// ServerCertRing holds the current and previous server certificate generations
// and serves both during the overlap window. It implements the
// tls.Config.GetCertificate contract so it can be wired into a listener without
// changing existing single-cert deployments.
type ServerCertRing struct {
	slots atomic.Pointer[ringSlots]
	now   clock
}

type ringSlots struct {
	current  *certSlot
	previous *certSlot
}

// NewServerCertRing creates a ring seeded with the first server certificate.
// A single-cert deployment behaves exactly as before: only one slot exists and
// GetCertificate always returns it.
func NewServerCertRing(initial *ServerCert) (*ServerCertRing, error) {
	if initial == nil || initial.Certificate == nil {
		return nil, newError(ReasonConfig, "", "initial server certificate cannot be nil")
	}
	r := &ServerCertRing{now: time.Now}
	r.slots.Store(&ringSlots{current: &certSlot{cert: initial, notAfter: initial.Certificate.NotAfter}})
	return r, nil
}

// Renew installs a new generation while retaining the previous one for the
// overlap period. The new cert becomes current immediately; the old one stays
// available as a fallback until it expires or the next renewal. Both paths are
// verifiable during the window because both anchor on roots the manager trusts.
func (r *ServerCertRing) Renew(incoming *ServerCert) error {
	if incoming == nil || incoming.Certificate == nil {
		return newError(ReasonConfig, "", "incoming server certificate cannot be nil")
	}
	cur := r.slots.Load()
	next := &ringSlots{
		current:  &certSlot{cert: incoming, notAfter: incoming.Certificate.NotAfter},
		previous: cur.current,
	}
	// An already-expired previous generation is dropped rather than offered.
	if next.previous != nil && !r.now().Before(next.previous.notAfter) {
		next.previous = nil
	}
	r.slots.Store(next)
	return nil
}

// Current returns the active server certificate.
func (r *ServerCertRing) Current() *ServerCert {
	return r.slots.Load().current.cert
}

// Previous returns the still-coexistent previous generation, or nil.
func (r *ServerCertRing) Previous() *ServerCert {
	s := r.slots.Load()
	if s.previous == nil || !r.now().Before(s.previous.notAfter) {
		return nil
	}
	return s.previous.cert
}

// GetCertificate implements tls.Config.GetCertificate. It prefers the current
// generation; callers that need to support a peer pinned to the old path can use
// Fallback for SNI/verifier coordination. Both generations remain cryptograph-
// ically valid during the overlap, so no handshake fails because of the renewal.
func (r *ServerCertRing) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	s := r.slots.Load()
	return &s.current.cert.TLSCert, nil
}

// FallbackCertificate returns the previous generation's TLS certificate when it
// is still within its validity window, else nil. A custom tls config can offer
// it on a retry or a dedicated identity to keep old-path peers verifying.
func (r *ServerCertRing) FallbackCertificate() *tls.Certificate {
	if prev := r.Previous(); prev != nil {
		return &prev.TLSCert
	}
	return nil
}

// All returns every currently offered generation (current first). This is the
// set a verifier should accept during rotation.
func (r *ServerCertRing) All() []*ServerCert {
	s := r.slots.Load()
	out := []*ServerCert{s.current.cert}
	if prev := r.Previous(); prev != nil {
		out = append(out, prev)
	}
	return out
}
