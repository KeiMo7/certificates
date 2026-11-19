package authority

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/smallstep/certificates/authority/config"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/db"
	"github.com/smallstep/certificates/revocation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBatchRevocationPropagationAcceptance(t *testing.T) {
	authDB, err := db.New(&db.Config{
		Type:       "badger",
		DataSource: t.TempDir(),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = authDB.Shutdown() })

	a := testAuthority(t, WithDatabase(authDB))
	a.config.Revocation = &config.RevocationConfig{
		Enabled:         true,
		RefreshInterval: &provisioner.Duration{Duration: time.Second},
		CacheDuration:   &provisioner.Duration{Duration: time.Second},
		CleanupInterval: &provisioner.Duration{Duration: time.Hour},
		FailurePolicy:   revocation.FailClosed,
	}

	now := time.Now().UTC()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	storer := authDB.(db.CertificateStorer)
	certs := make([]*x509.Certificate, 50)
	serials := make([]string, 50)
	for i := range certs {
		serial := big.NewInt(int64(i + 1))
		template := &x509.Certificate{
			SerialNumber: serial,
			Subject:      pkix.Name{CommonName: "compromised-host"},
			DNSNames:     []string{"compromised-host.example.com"},
			NotBefore:    now.Add(-time.Minute),
			NotAfter:     now.Add(10 * time.Minute),
			KeyUsage:     x509.KeyUsageDigitalSignature,
		}
		der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		require.NoError(t, err)
		cert, err := x509.ParseCertificate(der)
		require.NoError(t, err)
		require.NoError(t, storer.StoreCertificate(cert))
		certs[i] = cert
		serials[i] = cert.SerialNumber.String()
	}

	feed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		snapshot, err := a.GetRevocationSnapshot(time.Now())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		etag := `"` + snapshot.Version + `"`
		w.Header().Set("ETag", etag)
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(snapshot)
	}))
	defer feed.Close()

	const verifierCount = 3
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	clients := make([]*revocation.Client, verifierCount)
	for i := range clients {
		client, err := revocation.NewClient(feed.URL, revocation.ClientOptions{
			RefreshInterval: 10 * time.Millisecond,
			MaxAge:          2 * time.Second,
			FailurePolicy:   revocation.FailClosed,
			Logger:          log.New(io.Discard, "", 0),
		})
		require.NoError(t, err)
		require.NoError(t, client.Refresh(ctx))
		require.NoError(t, client.Check(certs[0]))
		clients[i] = client
	}

	var wg sync.WaitGroup
	for _, client := range clients {
		wg.Add(1)
		go func(c *revocation.Client) {
			defer wg.Done()
			c.Run(ctx)
		}(client)
	}

	preview, err := a.PreviewRevokeBatch(context.Background(), &RevokeBatchOptions{
		Serials:    serials,
		ReasonCode: 4,
		Reason:     "host compromise",
	})
	require.NoError(t, err)
	require.Equal(t, 50, preview.Affected)

	type measurement struct {
		latency time.Duration
		allowed int
	}
	results := make(chan measurement, verifierCount)
	start := time.Now()
	for _, client := range clients {
		go func(c *revocation.Client) {
			var allowed int
			for {
				err := c.Check(certs[0])
				switch {
				case errors.Is(err, revocation.ErrRevoked):
					results <- measurement{latency: time.Since(start), allowed: allowed}
					return
				case err != nil:
					results <- measurement{latency: -1, allowed: allowed}
					return
				default:
					allowed++
					time.Sleep(time.Millisecond)
				}
			}
		}(client)
	}

	result, err := a.RevokeBatch(context.Background(), &RevokeBatchOptions{
		Serials:      serials,
		ReasonCode:   4,
		Reason:       "host compromise",
		Confirmation: preview.Confirmation,
	})
	require.NoError(t, err)
	require.Equal(t, 50, result.Revoked)

	var maxLatency time.Duration
	var allowedDuring int
	for i := 0; i < verifierCount; i++ {
		select {
		case got := <-results:
			require.GreaterOrEqual(t, got.latency, time.Duration(0))
			if got.latency > maxLatency {
				maxLatency = got.latency
			}
			allowedDuring += got.allowed
		case <-time.After(3 * time.Second):
			t.Fatal("timed out waiting for revocation propagation")
		}
	}

	snapshot, err := a.GetRevocationSnapshot(time.Now())
	require.NoError(t, err)
	require.Len(t, snapshot.Revocations, 50)

	deleted, err := a.CleanupExpiredRevocations(now.Add(11 * time.Minute))
	require.NoError(t, err)
	assert.Equal(t, 50, deleted)

	afterCleanup, err := a.GetRevocationSnapshot(now.Add(11 * time.Minute))
	require.NoError(t, err)
	assert.Empty(t, afterCleanup.Revocations)

	t.Logf("batch revocation acceptance: verifiers=%d propagation_max=%s allowed_during=%d records_growth=0->50->0",
		verifierCount, maxLatency, allowedDuring)
}
