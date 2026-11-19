package revocation

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testCertificate(serial int64, notAfter time.Time) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		NotAfter:     notAfter,
	}
}

func TestClientFailurePolicies(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "offline", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	now := time.Now().UTC()
	cert := testCertificate(42, now.Add(10*time.Minute))

	t.Run("fail closed", func(t *testing.T) {
		var logs bytes.Buffer
		client, err := NewClient(server.URL, ClientOptions{
			FailurePolicy: FailClosed,
			Logger:        log.New(&logs, "", 0),
			Now:           func() time.Time { return now },
		})
		require.NoError(t, err)

		assert.ErrorIs(t, client.Check(cert), ErrUnavailable)
		stats := client.Stats()
		assert.Equal(t, uint64(1), stats.Denied)
		assert.Equal(t, uint64(1), stats.Degraded)
		assert.Contains(t, logs.String(), "degraded")
	})

	t.Run("fail open", func(t *testing.T) {
		var logs bytes.Buffer
		client, err := NewClient(server.URL, ClientOptions{
			FailurePolicy: FailOpen,
			Logger:        log.New(&logs, "", 0),
			Now:           func() time.Time { return now },
		})
		require.NoError(t, err)

		require.NoError(t, client.Check(cert))
		stats := client.Stats()
		assert.Equal(t, uint64(1), stats.Allowed)
		assert.Equal(t, uint64(1), stats.Degraded)
		assert.Contains(t, logs.String(), "fail-open")
	})

	t.Run("natural expiry", func(t *testing.T) {
		client, err := NewClient(server.URL, ClientOptions{
			FailurePolicy: FailClosed,
			Now:           func() time.Time { return now },
		})
		require.NoError(t, err)

		expired := testCertificate(43, now.Add(-time.Second))
		require.NoError(t, client.Check(expired))
		assert.Equal(t, uint64(1), client.Stats().Allowed)
	})
}

func TestClientRefreshAndCheck(t *testing.T) {
	now := time.Now().UTC()
	expiresAt := now.Add(10 * time.Minute)
	snapshot := Snapshot{
		GeneratedAt:   now,
		NextUpdate:    now.Add(5 * time.Second),
		CacheDuration: 30,
		FailurePolicy: FailClosed,
		Revocations: []Entry{{
			Serial:     "42",
			RevokedAt:  now,
			ExpiresAt:  &expiresAt,
			ReasonCode: 4,
		}},
	}
	snapshot.Version = snapshot.ComputeETag()

	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("ETag", `"`+snapshot.Version+`"`)
		if r.Header.Get("If-None-Match") == `"`+snapshot.Version+`"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(snapshot))
	}))
	defer server.Close()

	client, err := NewClient(server.URL, ClientOptions{
		FailurePolicy: FailClosed,
		Now:           func() time.Time { return now },
	})
	require.NoError(t, err)
	require.NoError(t, client.Refresh(context.Background()))

	assert.ErrorIs(t, client.Check(testCertificate(42, expiresAt)), ErrRevoked)
	require.NoError(t, client.Check(testCertificate(43, expiresAt)))

	require.NoError(t, client.Refresh(context.Background()))
	assert.Equal(t, 2, requests)
	assert.Equal(t, uint64(2), client.Stats().Refreshes)
}

func TestClientStaleCache(t *testing.T) {
	now := time.Now().UTC()
	expiresAt := now.Add(10 * time.Minute)
	snapshot := Snapshot{
		GeneratedAt:   now,
		NextUpdate:    now.Add(5 * time.Second),
		CacheDuration: 5,
		FailurePolicy: FailClosed,
		Revocations: []Entry{{
			Serial:    "42",
			RevokedAt: now,
			ExpiresAt: &expiresAt,
		}},
	}
	snapshot.Version = snapshot.ComputeETag()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, json.NewEncoder(w).Encode(snapshot))
	}))
	defer server.Close()

	client, err := NewClient(server.URL, ClientOptions{
		FailurePolicy: FailClosed,
		MaxAge:        time.Second,
		Now:           func() time.Time { return now },
	})
	require.NoError(t, err)
	require.NoError(t, client.Refresh(context.Background()))
	assert.ErrorIs(t, client.Check(testCertificate(42, expiresAt)), ErrRevoked)

	now = now.Add(2 * time.Second)
	assert.ErrorIs(t, client.Check(testCertificate(42, expiresAt)), ErrUnavailable)
}

func TestSnapshotComputeETag(t *testing.T) {
	expiresAt := time.Unix(100, 0).UTC()
	a := Snapshot{Revocations: []Entry{
		{Serial: "2", RevokedAt: time.Unix(20, 0), ExpiresAt: &expiresAt, ReasonCode: 1},
		{Serial: "1", RevokedAt: time.Unix(10, 0), ExpiresAt: &expiresAt, ReasonCode: 1},
	}}
	b := Snapshot{Revocations: []Entry{
		{Serial: "1", RevokedAt: time.Unix(10, 0), ExpiresAt: &expiresAt, ReasonCode: 1},
		{Serial: "2", RevokedAt: time.Unix(20, 0), ExpiresAt: &expiresAt, ReasonCode: 1},
	}}
	assert.Equal(t, a.ComputeETag(), b.ComputeETag())

	b.Revocations[1].ReasonCode = 4
	assert.NotEqual(t, a.ComputeETag(), b.ComputeETag())
}

func TestClientRunStopsWithContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "offline", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	var logs bytes.Buffer
	client, err := NewClient(server.URL, ClientOptions{
		FailurePolicy:   FailClosed,
		RefreshInterval: time.Millisecond,
		Logger:          log.New(&logs, "", 0),
	})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		client.Run(ctx)
		close(done)
	}()
	require.Eventually(t, func() bool {
		return client.Stats().RefreshErrors > 0
	}, time.Second, time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("client did not stop")
	}
	assert.Contains(t, logs.String(), "degraded")
	assert.False(t, errors.Is(client.LastError(), ErrRevoked))
}
