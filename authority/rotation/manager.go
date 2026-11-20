package rotation

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// MinOverlap is the minimum required overlap, in seconds, between an outgoing
// root's trust window and an incoming root's window. Deployments may require a
// larger value via WithMinOverlap. A non-positive value disables the check
// (not recommended).
const defaultMinOverlap = 0

// clock allows tests to control time deterministically.
type clock func() time.Time

// Manager is the concurrency-safe owner of a root rotation set.
//
// All reads are served from an immutable snapshot pointer, so verification and
// issuance never observe a partially applied change. Reloads build a brand new
// snapshot and atomically swap it in only after the candidate passes every
// validation; a rejected reload leaves the running set untouched, so there is
// never a window in which no root is usable.
type Manager struct {
	mu         sync.Mutex // serializes reload/transition writers
	snap       atomic.Pointer[snapshot]
	now        clock
	minOverlap time.Duration

	// per-root CRL holders, keyed by root id. These survive reloads so a failed
	// CRL regeneration can fall back to the last good list.
	crlMu sync.Mutex
	crls  map[string]*crlHolder

	// leaves is the authoritative leaf -> root reverse index, populated at
	// signing time. Guarded by mu.
	leaves *leafIndex
}

// sortEntries orders entries by window start, then by id for stable ties.
func sortEntries(entries []*rootEntry) {
	sort.Slice(entries, func(i, j int) bool {
		ti, tj := entries[i].notBefore, entries[j].notBefore
		if !ti.Equal(tj) {
			return ti.Before(tj)
		}
		return entries[i].id < entries[j].id
	})
}

// Option configures a Manager.
type Option func(*Manager)

// WithClock overrides the time source (used by tests).
func WithClock(c func() time.Time) Option {
	return func(m *Manager) {
		if c != nil {
			m.now = c
		}
	}
}

// WithMinOverlap sets the minimum required overlap between adjacent root
// trust windows during a rotation.
func WithMinOverlap(d time.Duration) Option {
	return func(m *Manager) { m.minOverlap = d }
}

// NewManager builds a Manager from the given root configurations. It validates
// the whole set up front and returns a typed config error without constructing
// a usable manager if anything is wrong, so a bad deploy fails at load time.
func NewManager(configs []RootConfig, opts ...Option) (*Manager, error) {
	m := &Manager{
		now:        time.Now,
		minOverlap: defaultMinOverlap,
		crls:       map[string]*crlHolder{},
	}
	for _, o := range opts {
		o(m)
	}
	snap, err := m.buildSnapshot(nil, configs)
	if err != nil {
		return nil, err
	}
	m.snap.Store(snap)
	return m, nil
}

// snapshot is an immutable view of the whole root set at a point in time.
type snapshot struct {
	order []*rootEntry // stable, sorted by notBefore then id
	byID  map[string]*rootEntry
	bySKI map[string]*rootEntry // root SubjectKeyId -> root
	byFP  map[string]*rootEntry
	// byIntermediateSKI maps every intermediate certificate's SKI in every
	// registered issuer chain to its owning root. This lets the engine resolve a
	// leaf's AKI (which names its intermediate, not the root) up to the anchoring
	// root structurally.
	byIntermediateSKI map[string]*rootEntry
}

func (s *snapshot) get(id string) (*rootEntry, bool) {
	r, ok := s.byID[id]
	return r, ok
}

// buildSnapshot validates configs against the previous snapshot (nil on first
// load) and produces a new immutable snapshot. It enforces every hard
// constraint in one place so both initial load and online reload share it.
func (m *Manager) buildSnapshot(prev *snapshot, configs []RootConfig) (*snapshot, error) {
	if len(configs) == 0 {
		return nil, newError(ReasonConfig, "", "root set must contain at least one root")
	}

	next := &snapshot{
		byID:              map[string]*rootEntry{},
		bySKI:             map[string]*rootEntry{},
		byFP:              map[string]*rootEntry{},
		byIntermediateSKI: map[string]*rootEntry{},
	}

	for i := range configs {
		cfg := configs[i]
		if cfg.Certificate == nil {
			return nil, newError(ReasonConfig, cfg.ID, "root configuration is missing a certificate")
		}
		fp := Fingerprint(cfg.Certificate.Raw)
		id := cfg.ID
		if id == "" {
			id = fp
		}
		if _, dup := next.byID[id]; dup {
			return nil, newError(ReasonConfig, id, "duplicate root id in configuration")
		}
		if !cfg.NotAfter.IsZero() && !cfg.NotBefore.IsZero() && !cfg.NotAfter.After(cfg.NotBefore) {
			return nil, newError(ReasonConfig, id, "root NotAfter must be after NotBefore")
		}

		entry := &rootEntry{
			id:        id,
			fp:        fp,
			cert:      cfg.Certificate,
			state:     cfg.State,
			notBefore: cfg.NotBefore,
			notAfter:  cfg.NotAfter,
			ski:       cfg.Certificate.SubjectKeyId,
		}

		// Carry over non-declarative runtime state and validate transitions.
		if prev != nil {
			if old, ok := prev.byID[id]; ok {
				if !old.state.canTransitionTo(cfg.State) {
					return nil, newError(ReasonConfig, id,
						"illegal lifecycle regression: %s -> %s; state may only move trusted -> stopped -> retired",
						old.state, cfg.State)
				}
				entry.issuer = old.issuer
				entry.issued = old.issued
			}
		}

		next.byID[id] = entry
		if len(entry.ski) > 0 {
			if _, dup := next.bySKI[string(entry.ski)]; dup {
				return nil, newError(ReasonConfig, id, "duplicate root SubjectKeyId in configuration")
			}
			next.bySKI[string(entry.ski)] = entry
		}
		next.byFP[fp] = entry
	}

	// A root that disappeared from config is not allowed: removal is an
	// explicit retirement, never an implicit drop, so previously issued
	// certificates remain identifiable.
	if prev != nil {
		for id := range prev.byID {
			if _, ok := next.byID[id]; !ok {
				return nil, newError(ReasonConfig, id,
					"root cannot be silently removed; retire it (state=retired) instead so issued certificates remain identifiable")
			}
		}
	}

	// Deterministic order: earliest window start first, ties broken by id. This
	// makes selection independent of configuration/load order.
	entries := make([]*rootEntry, 0, len(next.byID))
	for _, e := range next.byID {
		entries = append(entries, e)
	}
	sortEntries(entries)
	next.order = entries

	// Window overlap check between adjacent roots. An incoming root must become
	// trusted before each overlapping outgoing root stops being trusted, by at
	// least minOverlap. We compare every pair of roots whose windows intersect.
	if m.minOverlap > 0 {
		if err := checkOverlaps(entries, m.minOverlap); err != nil {
			return nil, err
		}
	}

	// Hard constraint: the set must always contain at least one root that is
	// StateTrusted and inside its window, so the CA is never structurally without
	// a potential issuer. On an online reload of a running manager we tighten this
	// to require a root with usable signing material already registered.
	t := m.now()
	if prev == nil {
		hasPotentialIssuer := false
		for _, e := range entries {
			if e.effectiveState(t) == StateTrusted && e.inWindow(t) {
				hasPotentialIssuer = true
				break
			}
		}
		if !hasPotentialIssuer {
			return nil, newError(ReasonNoIssuer, "",
				"configuration rejected: no trusted, in-window root exists at %s",
				t.UTC().Format(time.RFC3339))
		}
	} else {
		hasIssuer := false
		for _, e := range entries {
			if e.canIssue(t) {
				hasIssuer = true
				break
			}
		}
		if !hasIssuer {
			return nil, newError(ReasonNoIssuer, "",
				"configuration rejected: no root is able to issue at %s; refusing to leave the CA without an issuing root",
				t.UTC().Format(time.RFC3339))
		}
	}

	return next, nil
}

// checkOverlaps ensures that whenever one root's trust window ends, another
// root that can take over is already trusted with at least the required margin.
func checkOverlaps(entries []*rootEntry, min time.Duration) error {
	for i := 0; i < len(entries); i++ {
		for j := i + 1; j < len(entries); j++ {
			a, b := entries[i], entries[j]
			// Only consider roots that have finite windows.
			if a.notAfter.IsZero() || b.notAfter.IsZero() || a.notBefore.IsZero() || b.notBefore.IsZero() {
				continue
			}
			// Overlap length of the two windows.
			start := maxTime(a.notBefore, b.notBefore)
			end := minTime(a.notAfter, b.notAfter)
			if !end.After(start) {
				// Non-overlapping windows: if a is trusted before b and a ends
				// before b starts, there is a trust gap between them.
				if a.notAfter.Before(b.notBefore) || a.notAfter.Equal(b.notBefore) {
					return newError(ReasonConfig, b.id,
						"trust gap: root %q window ends %s before root %q starts %s; clients holding only %q would fail",
						a.id, a.notAfter.UTC().Format(time.RFC3339), b.id,
						b.notBefore.UTC().Format(time.RFC3339), a.id)
				}
				continue
			}
			if end.Sub(start) < min {
				return newError(ReasonConfig, b.id,
					"overlap between root %q and root %q is %s, less than required %s",
					a.id, b.id, end.Sub(start), min)
			}
		}
	}
	return nil
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

// Reload applies a new configuration online. It builds a validated candidate
// from the current snapshot and swaps it atomically. On any validation error
// the current set keeps serving and the error is returned; callers should
// surface an alert but keep running.
func (m *Manager) Reload(configs []RootConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	candidate, err := m.buildSnapshot(m.snap.Load(), configs)
	if err != nil {
		return err
	}
	m.snap.Store(candidate)
	return nil
}

// snapshotNow returns the current snapshot and time.
func (m *Manager) snapshotNow() (*snapshot, time.Time) {
	return m.snap.Load(), m.now()
}

// ActiveIssuer returns the root that should sign new certificates at the
// current time. Selection is deterministic and independent of load order:
// among roots that can issue now, the one whose window started most recently is
// preferred (the newest generation), ties broken by id. This produces an
// automatic, restart-free cut-over when a newer root's NotBefore passes.
func (m *Manager) ActiveIssuer() (*rootEntry, error) {
	snap, t := m.snapshotNow()
	var best *rootEntry
	for _, e := range snap.order {
		if !e.canIssue(t) {
			continue
		}
		if best == nil || e.notBefore.After(best.notBefore) ||
			(e.notBefore.Equal(best.notBefore) && e.id > best.id) {
			best = e
		}
	}
	if best == nil {
		return nil, newError(ReasonNoIssuer, "", "no root is in state trusted and inside its validity window at %s",
			t.UTC().Format(time.RFC3339))
	}
	return best, nil
}
