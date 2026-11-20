package rotation

import (
	"crypto"
	"crypto/x509"
)

// SignRequest is a leaf certificate to be signed by the active issuing root.
type SignRequest struct {
	// Template is the leaf certificate template. Its Issuer and AKI are set by
	// the engine to match the selected issuer.
	Template *x509.Certificate

	// PublicKey is the leaf subject public key.
	PublicKey crypto.PublicKey
}

// SignResult returns the signed leaf and the full ordered chain
// (leaf, intermediate(s)..., root).
type SignResult struct {
	Leaf     *x509.Certificate
	Chain    []*x509.Certificate
	RootID   string
	RootCert *x509.Certificate
}

// RegisterIssuer binds signing material (intermediate chain + signer) to an
// existing root. This is how a root becomes able to issue. It is kept separate
// from the declarative RootConfig so reloads never need to carry private keys.
func (m *Manager) RegisterIssuer(rootID string, iss Issuer) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	snap := m.snap.Load()
	entry, ok := snap.byID[rootID]
	if !ok {
		return newError(ReasonConfig, rootID, "cannot register issuer: unknown root id")
	}
	if iss.Signer == nil {
		return newError(ReasonConfig, rootID, "issuer signer cannot be nil")
	}
	if len(iss.Chain) == 0 {
		return newError(ReasonConfig, rootID, "issuer chain cannot be empty")
	}
	// The chain must terminate in the root it is being registered against.
	last := iss.Chain[len(iss.Chain)-1]
	if Fingerprint(last.Raw) != entry.fp {
		return newError(ReasonConfig, rootID, "issuer chain does not terminate in this root")
	}

	// Rebuild the snapshot with the issuer attached. Entries are immutable, so
	// copy-on-write.
	ns := snap.clone()
	ne := *entry
	ne.issuer = &iss
	ns.byID[rootID] = &ne
	ns.reindex()
	m.snap.Store(ns)
	return nil
}

// Sign creates a leaf certificate signed by the currently active issuing root.
// It selects the issuer deterministically, stamps the correct Issuer/AKI on the
// template, signs it, and records the leaf -> root link so the relationship can
// be reverse-checked later without relying on fingerprint string matching.
func (m *Manager) Sign(req SignRequest) (*SignResult, error) {
	if req.Template == nil {
		return nil, newError(ReasonConfig, "", "sign request template cannot be nil")
	}
	if req.PublicKey == nil {
		return nil, newError(ReasonConfig, "", "sign request public key cannot be nil")
	}

	entry, err := m.ActiveIssuer()
	if err != nil {
		return nil, err
	}
	iss := entry.issuer
	parent := iss.Chain[0]

	// Bind the leaf to this issuer through the standard X.509 issuer link.
	tpl := req.Template
	tpl.Issuer = parent.Subject
	if len(parent.SubjectKeyId) > 0 {
		tpl.AuthorityKeyId = append([]byte(nil), parent.SubjectKeyId...)
	}

	leafDER, err := x509.CreateCertificate(nil, tpl, parent, req.PublicKey, iss.Signer)
	if err != nil {
		return nil, newError(ReasonConfig, entry.id, "failed to sign leaf: %v", err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return nil, newError(ReasonConfig, entry.id, "failed to parse signed leaf: %v", err)
	}

	// Copy-on-write increment of the per-root issued counter and record of the
	// reverse link.
	m.mu.Lock()
	snap := m.snap.Load()
	ns := snap.clone()
	if cur, ok := ns.byID[entry.id]; ok {
		ne := *cur
		ne.issued++
		ns.byID[entry.id] = &ne
	}
	ns.reindex()
	m.snap.Store(ns)
	if m.leaves == nil {
		m.leaves = newLeafIndex()
	}
	m.leaves.bySerial[serialKey(leaf)] = entry.id
	m.mu.Unlock()

	chain := append([]*x509.Certificate{leaf}, iss.Chain...)
	return &SignResult{
		Leaf:     leaf,
		Chain:    chain,
		RootID:   entry.id,
		RootCert: entry.cert,
	}, nil
}

// leafIndex maps a signed leaf's serial (DER) to the id of the root that signed
// it. It is the authoritative reverse-lookup relationship; AKI/SKI matching is
// used only for certificates issued before/outside this engine.
type leafIndex struct {
	bySerial map[string]string
}

func newLeafIndex() *leafIndex { return &leafIndex{bySerial: map[string]string{}} }

func serialKey(c *x509.Certificate) string {
	if c.SerialNumber == nil {
		return ""
	}
	return string(c.SerialNumber.Bytes())
}

// RootForCertificate returns the id of the root that issued the given
// certificate. It first consults the authoritative issuance index, then falls
// back to the standards-based AKI -> root SKI link. It never relies on a
// fingerprint string comparison alone.
func (m *Manager) RootForCertificate(c *x509.Certificate) (string, error) {
	if c == nil {
		return "", newError(ReasonBrokenChain, "", "certificate cannot be nil")
	}
	snap := m.snap.Load()

	// 1) Authoritative index populated at signing time.
	if m.leaves != nil {
		if id, ok := m.leaves.bySerial[serialKey(c)]; ok {
			return id, nil
		}
	}

	// 2) Standards-based issuer link: leaf AKI -> root/intermediate SKI, walking
	// up to the anchoring root.
	id, err := snap.rootIDByAKI(c)
	if err != nil {
		return "", err
	}
	return id, nil
}

// rootIDByAKI resolves a certificate's AuthorityKeyId up to the anchoring root.
// A leaf's AKI names its immediate issuer (usually an intermediate), so the
// lookup first checks the intermediate-SKI index and, failing that, the root-SKI
// index. Returns a typed error naming the missing link when nothing matches.
func (s *snapshot) rootIDByAKI(c *x509.Certificate) (string, error) {
	aki := c.AuthorityKeyId
	if len(aki) == 0 {
		// Last-resort structural match via issuer name.
		for _, e := range s.order {
			if e.cert.Subject.String() == c.Issuer.String() {
				return e.id, nil
			}
		}
		return "", newError(ReasonBrokenChain, "", "certificate has no AuthorityKeyId and no matching issuer")
	}
	key := string(aki)
	if e, ok := s.byIntermediateSKI[key]; ok {
		return e.id, nil
	}
	if e, ok := s.bySKI[key]; ok {
		return e.id, nil
	}
	// Fallback for a root whose issuer chain is not (yet) registered: match by
	// issuer name against a known root or one of its intermediates so the caller
	// can distinguish "root known but chain missing" from "wholly unknown root".
	if id, ok := s.rootIDByIssuerName(c); ok {
		return id, nil
	}
	return "", newError(ReasonNoRoot, "", "no root with SubjectKeyId %x anchors this certificate", aki).
		withMissing(aki)
}

// rootIDByIssuerName matches a certificate's Issuer name against every known
// root subject and every registered intermediate subject.
func (s *snapshot) rootIDByIssuerName(c *x509.Certificate) (string, bool) {
	for _, e := range s.order {
		if e.cert.Subject.String() == c.Issuer.String() {
			return e.id, true
		}
		if e.issuer != nil {
			for _, inter := range e.issuer.Chain {
				if inter.Subject.String() == c.Issuer.String() {
					return e.id, true
				}
			}
		}
	}
	return "", false
}

// clone returns a shallow, independently-writable copy of the snapshot maps.
func (s *snapshot) clone() *snapshot {
	ns := &snapshot{
		order:             append([]*rootEntry(nil), s.order...),
		byID:              map[string]*rootEntry{},
		bySKI:             map[string]*rootEntry{},
		byFP:              map[string]*rootEntry{},
		byIntermediateSKI: map[string]*rootEntry{},
	}
	for k, v := range s.byID {
		ns.byID[k] = v
	}
	// Copy intermediate index; reindex() rebuilds it from issuers anyway, but
	// keep the clone valid even if called standalone.
	for k, v := range s.byIntermediateSKI {
		ns.byIntermediateSKI[k] = v
	}
	return ns
}

// reindex rebuilds the SKI/fingerprint/intermediate maps and ordered slice.
func (s *snapshot) reindex() {
	s.bySKI = map[string]*rootEntry{}
	s.byFP = map[string]*rootEntry{}
	s.byIntermediateSKI = map[string]*rootEntry{}
	for _, e := range s.byID {
		if len(e.ski) > 0 {
			s.bySKI[string(e.ski)] = e
		}
		s.byFP[e.fp] = e
		if e.issuer != nil {
			// All chain entries except the final root are intermediates that
			// ultimately chain to this root.
			for _, inter := range e.issuer.Chain[:len(e.issuer.Chain)-1] {
				if len(inter.SubjectKeyId) > 0 {
					s.byIntermediateSKI[string(inter.SubjectKeyId)] = e
				}
			}
		}
	}
	ordered := make([]*rootEntry, 0, len(s.byID))
	for _, e := range s.byID {
		ordered = append(ordered, e)
	}
	sortEntries(ordered)
	s.order = ordered
}
