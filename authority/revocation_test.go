package authority

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/smallstep/certificates/authority/config"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/db"
	"github.com/smallstep/certificates/revocation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func batchTestCertificate(serial int64, now time.Time) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "compromised-host"},
		DNSNames:     []string{"compromised-host.example.com"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(10 * time.Minute),
	}
}

func TestAuthority_PreviewAndRevokeBatch(t *testing.T) {
	now := time.Now().UTC()
	certs := make(map[string]*x509.Certificate)
	serials := make([]string, 0, 50)
	for i := int64(1); i <= 50; i++ {
		cert := batchTestCertificate(i, now)
		serials = append(serials, cert.SerialNumber.String())
		certs[cert.SerialNumber.String()] = cert
	}

	var batch []*db.RevokedCertificateInfo
	a := testAuthority(t, WithDatabase(&db.MockAuthDB{
		MGetCertificate: func(serial string) (*x509.Certificate, error) {
			cert, ok := certs[serial]
			if !ok {
				return nil, errors.New("not found")
			}
			return cert, nil
		},
		MIsRevoked: func(string) (bool, error) { return false, nil },
		MRevokeBatch: func(records []*db.RevokedCertificateInfo) error {
			batch = records
			return nil
		},
	}))
	a.config.Revocation = &config.RevocationConfig{Enabled: true}

	preview, err := a.PreviewRevokeBatch(context.Background(), &RevokeBatchOptions{
		Serials:    serials,
		Reason:     "host compromise",
		ReasonCode: 4,
	})
	require.NoError(t, err)
	assert.Len(t, preview.Certificates, 50)
	assert.Equal(t, 50, preview.Affected)
	assert.NotEmpty(t, preview.Confirmation)

	_, err = a.RevokeBatch(context.Background(), &RevokeBatchOptions{
		Serials:      serials[:49],
		Reason:       "host compromise",
		ReasonCode:   4,
		Confirmation: preview.Confirmation,
	})
	require.Error(t, err)
	assert.Nil(t, batch)

	result, err := a.RevokeBatch(context.Background(), &RevokeBatchOptions{
		Serials:      serials,
		Reason:       "host compromise",
		ReasonCode:   4,
		Confirmation: preview.Confirmation,
	})
	require.NoError(t, err)
	assert.Equal(t, 50, result.Revoked)
	require.Len(t, batch, 50)
	for _, record := range batch {
		require.Contains(t, certs, record.Serial)
		assert.Equal(t, "host compromise", record.Reason)
		assert.Equal(t, 4, record.ReasonCode)
		assert.Equal(t, certs[record.Serial].NotAfter, record.ExpiresAt)
	}
}

func TestAuthority_RevokeBatchRejectsUnknownOrExpired(t *testing.T) {
	now := time.Now().UTC()
	expired := batchTestCertificate(1, now)
	expired.NotAfter = now.Add(-time.Second)

	a := testAuthority(t, WithDatabase(&db.MockAuthDB{
		MGetCertificate: func(serial string) (*x509.Certificate, error) {
			if serial == "1" {
				return expired, nil
			}
			return nil, errors.New("not found")
		},
		MIsRevoked: func(string) (bool, error) { return false, nil },
	}))
	a.config.Revocation = &config.RevocationConfig{Enabled: true}

	_, err := a.PreviewRevokeBatch(context.Background(), &RevokeBatchOptions{
		Serials:    []string{"1"},
		ReasonCode: 4,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already expired")

	_, err = a.PreviewRevokeBatch(context.Background(), &RevokeBatchOptions{
		Serials:    []string{"2"},
		ReasonCode: 4,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "was not found")
}

func TestAuthority_GetRevocationSnapshot(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	validExpiry := now.Add(5 * time.Minute)
	expiredExpiry := now.Add(-time.Minute)
	list := []db.RevokedCertificateInfo{
		{Serial: "2", RevokedAt: now.Add(-time.Minute), ExpiresAt: validExpiry, ReasonCode: 4},
		{Serial: "1", RevokedAt: now.Add(-time.Minute), ExpiresAt: expiredExpiry, ReasonCode: 1},
		{Serial: "3", RevokedAt: now.Add(-time.Minute)},
	}

	a := testAuthority(t, WithDatabase(&db.MockAuthDB{
		MGetRevokedCertificates: func() (*[]db.RevokedCertificateInfo, error) {
			return &list, nil
		},
	}))
	a.config.Revocation = &config.RevocationConfig{
		Enabled:         true,
		RefreshInterval: &provisioner.Duration{Duration: 5 * time.Second},
		CacheDuration:   &provisioner.Duration{Duration: 2 * time.Second},
		FailurePolicy:   revocation.FailClosed,
	}

	snapshot, err := a.GetRevocationSnapshot(now)
	require.NoError(t, err)
	require.Len(t, snapshot.Revocations, 2)
	assert.Equal(t, "2", snapshot.Revocations[0].Serial)
	assert.Equal(t, "3", snapshot.Revocations[1].Serial)
	assert.Equal(t, int64(2), snapshot.CacheDuration)
	assert.Equal(t, revocation.FailClosed, snapshot.FailurePolicy)
	assert.Equal(t, now.Add(5*time.Second), snapshot.NextUpdate)
	assert.NotEmpty(t, snapshot.Version)

	snapshot2, err := a.GetRevocationSnapshot(now.Add(time.Second))
	require.NoError(t, err)
	assert.Equal(t, snapshot.Version, snapshot2.Version)
}

func TestAuthority_CleanupExpiredRevocations(t *testing.T) {
	now := time.Now().UTC()
	var cutoff time.Time
	a := testAuthority(t, WithDatabase(&db.MockAuthDB{
		MDeleteExpiredRevocations: func(t time.Time) (int, error) {
			cutoff = t
			return 7, nil
		},
	}))
	a.config.Revocation = &config.RevocationConfig{
		Enabled:   true,
		Retention: &provisioner.Duration{Duration: time.Hour},
	}

	deleted, err := a.CleanupExpiredRevocations(now)
	require.NoError(t, err)
	assert.Equal(t, 7, deleted)
	assert.Equal(t, now.Add(-time.Hour), cutoff)
}
