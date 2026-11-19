// Package revocation implements the polling side of the short-lived
// certificate revocation feed.
//
// The feed is deliberately pull based. Edge verifiers can refresh it at their
// own cadence, and a verifier that cannot reach the CA can choose to fail open
// or fail closed without requiring a persistent connection.
package revocation

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// DefaultRefreshInterval is the recommended interval between feed polls.
	DefaultRefreshInterval = 5 * time.Second
	// DefaultMaxAge is used when neither the client nor the snapshot specifies
	// how long a cached snapshot remains usable.
	DefaultMaxAge = 30 * time.Second
	// DefaultHTTPTimeout is the default timeout for a feed request.
	DefaultHTTPTimeout = 10 * time.Second

	maxSnapshotSize = 8 << 20
)

var (
	// ErrRevoked is returned when a certificate serial is present in a fresh
	// revocation snapshot.
	ErrRevoked = errors.New("certificate has been revoked")
	// ErrUnavailable is returned in fail-closed mode when no fresh revocation
	// snapshot is available.
	ErrUnavailable = errors.New("revocation status unavailable")
)

// FailurePolicy controls what a verifier does when it cannot obtain a fresh
// revocation snapshot.
type FailurePolicy string

const (
	// FailOpen allows the request when revocation status cannot be confirmed.
	FailOpen FailurePolicy = "fail-open"
	// FailClosed rejects the request when revocation status cannot be
	// confirmed.
	FailClosed FailurePolicy = "fail-closed"
)

// Validate validates a failure policy.
func (p FailurePolicy) Validate() error {
	switch p {
	case FailOpen, FailClosed:
		return nil
	default:
		return fmt.Errorf("invalid revocation failure policy %q", p)
	}
}

// Entry is a revocation record in a snapshot. ExpiresAt is the expiration of
// the certificate and bounds how long the record needs to be retained.
type Entry struct {
	Serial     string     `json:"serial"`
	RevokedAt  time.Time  `json:"revokedAt"`
	ExpiresAt  *time.Time `json:"expiresAt,omitempty"`
	ReasonCode int        `json:"reasonCode,omitempty"`
	Reason     string     `json:"reason,omitempty"`
}

// Snapshot is a complete, point-in-time revocation view. It is intentionally a
// full snapshot instead of an incremental log so a verifier that missed updates
// can recover with a single request.
type Snapshot struct {
	Version       string        `json:"version,omitempty"`
	GeneratedAt   time.Time     `json:"generatedAt"`
	NextUpdate    time.Time     `json:"nextUpdate"`
	CacheDuration int64         `json:"cacheDuration"`
	FailurePolicy FailurePolicy `json:"failurePolicy"`
	Revocations   []Entry       `json:"revocations"`
}

// ComputeETag returns a stable digest of the revocation entries. GeneratedAt
// and NextUpdate are intentionally excluded so unchanged feeds can use 304
// responses.
func (s *Snapshot) ComputeETag() string {
	entries := append([]Entry(nil), s.Revocations...)
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Serial < entries[j].Serial
	})

	h := sha256.New()
	for _, e := range entries {
		var expiresAt int64
		if e.ExpiresAt != nil {
			expiresAt = e.ExpiresAt.UnixNano()
		}
		fmt.Fprintf(h, "%s\x00%d\x00%d\x00%d\x00%s\x00", e.Serial, e.RevokedAt.UnixNano(), expiresAt, e.ReasonCode, e.Reason)
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// Stats contains verifier counters that can be exported by the embedding
// application or used in an acceptance test.
type Stats struct {
	Refreshes     uint64
	RefreshErrors uint64
	Checks        uint64
	Allowed       uint64
	Revoked       uint64
	Denied        uint64
	Degraded      uint64
}

type counters struct {
	refreshes     atomic.Uint64
	refreshErrors atomic.Uint64
	checks        atomic.Uint64
	allowed       atomic.Uint64
	revoked       atomic.Uint64
	denied        atomic.Uint64
	degraded      atomic.Uint64
}

// ClientOptions configures a revocation feed client.
type ClientOptions struct {
	HTTPClient      *http.Client
	RefreshInterval time.Duration
	// MaxAge is the maximum age of a cached snapshot that may still be used.
	// A zero value uses the server-provided cache duration.
	MaxAge        time.Duration
	FailurePolicy FailurePolicy
	Logger        *log.Logger
	Now           func() time.Time
}

// Client polls a revocation snapshot endpoint and checks certificate serials
// against the most recent usable snapshot.
type Client struct {
	endpoint string
	opts     ClientOptions
	counters counters

	mu        sync.RWMutex
	snapshot  *Snapshot
	fetchedAt time.Time
	etag      string
	lastErr   error
}

// NewClient creates a polling revocation client.
func NewClient(endpoint string, opts ClientOptions) (*Client, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("parse revocation endpoint: %w", err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, fmt.Errorf("revocation endpoint must use http or https")
	}
	if opts.HTTPClient == nil {
		opts.HTTPClient = &http.Client{Timeout: DefaultHTTPTimeout}
	}
	if opts.RefreshInterval <= 0 {
		opts.RefreshInterval = DefaultRefreshInterval
	}
	if opts.FailurePolicy == "" {
		opts.FailurePolicy = FailClosed
	}
	if err := opts.FailurePolicy.Validate(); err != nil {
		return nil, err
	}
	if opts.Logger == nil {
		opts.Logger = log.Default()
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}

	return &Client{
		endpoint: endpoint,
		opts:     opts,
	}, nil
}

// Refresh fetches a new snapshot. A 304 response refreshes the local snapshot
// age without changing its contents.
func (c *Client) Refresh(ctx context.Context) error {
	c.mu.RLock()
	etag := c.etag
	c.mu.RUnlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint, nil)
	if err != nil {
		return c.recordRefreshError(err)
	}
	req.Header.Set("Accept", "application/json")
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}

	resp, err := c.opts.HTTPClient.Do(req)
	if err != nil {
		return c.recordRefreshError(err)
	}
	defer resp.Body.Close()

	now := c.opts.Now().UTC()
	if resp.StatusCode == http.StatusNotModified {
		c.mu.Lock()
		if c.snapshot == nil {
			c.mu.Unlock()
			return c.recordRefreshError(errors.New("received 304 without a cached snapshot"))
		}
		c.fetchedAt = now
		c.lastErr = nil
		c.mu.Unlock()
		c.counters.refreshes.Add(1)
		return nil
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return c.recordRefreshError(fmt.Errorf("revocation feed returned %s: %s", resp.Status, strings.TrimSpace(string(body))))
	}

	var snapshot Snapshot
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxSnapshotSize)).Decode(&snapshot); err != nil {
		return c.recordRefreshError(fmt.Errorf("decode revocation snapshot: %w", err))
	}
	if snapshot.FailurePolicy != "" {
		if err := snapshot.FailurePolicy.Validate(); err != nil {
			return c.recordRefreshError(err)
		}
	}
	for i := range snapshot.Revocations {
		if snapshot.Revocations[i].Serial == "" {
			return c.recordRefreshError(errors.New("revocation snapshot contains an empty serial"))
		}
	}

	c.mu.Lock()
	c.snapshot = &snapshot
	c.fetchedAt = now
	c.lastErr = nil
	c.etag = resp.Header.Get("ETag")
	if c.etag == "" {
		c.etag = snapshot.Version
	}
	c.mu.Unlock()

	c.counters.refreshes.Add(1)
	return nil
}

func (c *Client) recordRefreshError(err error) error {
	c.counters.refreshErrors.Add(1)
	c.mu.Lock()
	c.lastErr = err
	c.mu.Unlock()
	return err
}

// Run polls the feed until the context is canceled.
func (c *Client) Run(ctx context.Context) {
	if err := c.Refresh(ctx); err != nil {
		c.opts.Logger.Printf("revocation: degraded: refresh failed: %v", err)
	}

	ticker := time.NewTicker(c.opts.RefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := c.Refresh(ctx); err != nil {
				c.opts.Logger.Printf("revocation: degraded: refresh failed: %v", err)
			}
		}
	}
}

// Check verifies the revocation status of an already-authenticated
// certificate. It does not perform certificate chain or signature validation;
// callers should keep using their existing x509 verification implementation
// first.
func (c *Client) Check(cert *x509.Certificate) error {
	if cert == nil || cert.SerialNumber == nil {
		return errors.New("revocation: certificate and serial number are required")
	}

	now := c.opts.Now().UTC()
	c.counters.checks.Add(1)

	// An expired certificate has failed its normal validity check already. Even
	// if the revocation feed is unavailable, short-lived certificates can fall
	// back to natural expiry.
	if !now.Before(cert.NotAfter) {
		c.counters.allowed.Add(1)
		return nil
	}

	c.mu.RLock()
	snapshot := c.snapshot
	fetchedAt := c.fetchedAt
	maxAge := c.cacheMaxAgeLocked()
	c.mu.RUnlock()

	if snapshot == nil || now.Sub(fetchedAt) > maxAge {
		c.counters.degraded.Add(1)
		switch c.opts.FailurePolicy {
		case FailOpen:
			c.opts.Logger.Printf("revocation: degraded: status unavailable for serial %s; allowing by fail-open policy", cert.SerialNumber)
			c.counters.allowed.Add(1)
			return nil
		default:
			c.opts.Logger.Printf("revocation: degraded: status unavailable for serial %s; rejecting by fail-closed policy", cert.SerialNumber)
			c.counters.denied.Add(1)
			return ErrUnavailable
		}
	}

	serial := cert.SerialNumber.String()
	for i := range snapshot.Revocations {
		entry := &snapshot.Revocations[i]
		if entry.Serial != serial {
			continue
		}
		if entry.ExpiresAt != nil && !now.Before(*entry.ExpiresAt) {
			continue
		}
		c.counters.revoked.Add(1)
		c.counters.denied.Add(1)
		return fmt.Errorf("%w: serial %s", ErrRevoked, serial)
	}

	c.counters.allowed.Add(1)
	return nil
}

func (c *Client) cacheMaxAgeLocked() time.Duration {
	if c.opts.MaxAge > 0 {
		return c.opts.MaxAge
	}
	if c.snapshot != nil && c.snapshot.CacheDuration > 0 {
		return time.Duration(c.snapshot.CacheDuration) * time.Second
	}
	return DefaultMaxAge
}

// Stats returns a point-in-time copy of the client counters.
func (c *Client) Stats() Stats {
	return Stats{
		Refreshes:     c.counters.refreshes.Load(),
		RefreshErrors: c.counters.refreshErrors.Load(),
		Checks:        c.counters.checks.Load(),
		Allowed:       c.counters.allowed.Load(),
		Revoked:       c.counters.revoked.Load(),
		Denied:        c.counters.denied.Load(),
		Degraded:      c.counters.degraded.Load(),
	}
}

// LastError returns the last refresh error, if any.
func (c *Client) LastError() error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lastErr
}

// Snapshot returns a copy of the most recently fetched snapshot.
func (c *Client) Snapshot() *Snapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.snapshot == nil {
		return nil
	}
	clone := *c.snapshot
	clone.Revocations = append([]Entry(nil), c.snapshot.Revocations...)
	return &clone
}
