package authority

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"sort"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/crypto/ocsp"

	"github.com/smallstep/certificates/authority/config"
	casapi "github.com/smallstep/certificates/cas/apiv1"
	"github.com/smallstep/certificates/db"
	"github.com/smallstep/certificates/errs"
	"github.com/smallstep/certificates/revocation"
)

const maxRevokeBatchSize = 1000

// RevokeBatchOptions are the options for an administrative batch revocation.
type RevokeBatchOptions struct {
	Serials      []string
	Reason       string
	ReasonCode   int
	Confirmation string
}

// RevokeBatchCertificate describes a certificate included in a preview.
type RevokeBatchCertificate struct {
	Serial    string   `json:"serial"`
	Subject   string   `json:"subject"`
	DNSNames  []string `json:"dnsNames,omitempty"`
	NotBefore string   `json:"notBefore"`
	NotAfter  string   `json:"notAfter"`
	Revoked   bool     `json:"revoked"`
}

// RevokeBatchPreview is returned before a batch is committed.
type RevokeBatchPreview struct {
	Confirmation   string                   `json:"confirmation"`
	Total          int                      `json:"total"`
	Affected       int                      `json:"affected"`
	AlreadyRevoked int                      `json:"alreadyRevoked"`
	Certificates   []RevokeBatchCertificate `json:"certificates"`
}

// RevokeBatchResult is returned after a batch is committed.
type RevokeBatchResult struct {
	Status         string `json:"status"`
	Revoked        int    `json:"revoked"`
	AlreadyRevoked int    `json:"alreadyRevoked"`
	Confirmation   string `json:"confirmation"`
}

// PreviewRevokeBatch resolves the requested serials and returns the exact set
// of certificates that would be revoked. The returned confirmation must be
// supplied to RevokeBatch.
func (a *Authority) PreviewRevokeBatch(ctx context.Context, opts *RevokeBatchOptions) (*RevokeBatchPreview, error) {
	serials, err := validateRevokeBatchOptions(opts)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	preview := &RevokeBatchPreview{
		Confirmation: revokeBatchConfirmation(serials, opts.ReasonCode, opts.Reason),
		Total:        len(serials),
		Certificates: make([]RevokeBatchCertificate, 0, len(serials)),
	}

	for _, serial := range serials {
		cert, err := a.db.GetCertificate(serial)
		if err != nil {
			return nil, errs.BadRequest("certificate with serial number %s was not found", serial)
		}
		if !now.Before(cert.NotAfter) {
			return nil, errs.BadRequest("certificate with serial number %s has already expired; natural expiry is sufficient", serial)
		}

		revoked, err := a.IsRevoked(serial)
		if err != nil {
			return nil, errs.Wrap(http.StatusInternalServerError, err, "authority.PreviewRevokeBatch; error checking revocation status")
		}
		if revoked {
			preview.AlreadyRevoked++
		} else {
			preview.Affected++
		}
		preview.Certificates = append(preview.Certificates, RevokeBatchCertificate{
			Serial:    serial,
			Subject:   cert.Subject.String(),
			DNSNames:  append([]string(nil), cert.DNSNames...),
			NotBefore: cert.NotBefore.UTC().Format(time.RFC3339),
			NotAfter:  cert.NotAfter.UTC().Format(time.RFC3339),
			Revoked:   revoked,
		})
	}

	_ = ctx
	return preview, nil
}

// RevokeBatch revokes a set of certificates atomically. The caller must first
// call PreviewRevokeBatch and supply its confirmation string.
func (a *Authority) RevokeBatch(ctx context.Context, opts *RevokeBatchOptions) (*RevokeBatchResult, error) {
	if opts == nil {
		return nil, errs.BadRequest("batch revocation options are required")
	}
	if opts.Confirmation == "" {
		return nil, errs.BadRequest("batch revocation confirmation is required; call the preview endpoint first")
	}

	serials, err := validateRevokeBatchOptions(opts)
	if err != nil {
		return nil, err
	}
	confirmation := revokeBatchConfirmation(serials, opts.ReasonCode, opts.Reason)
	if opts.Confirmation != confirmation {
		return nil, errs.BadRequest("batch revocation confirmation does not match the requested certificate list")
	}

	now := time.Now().UTC()
	records := make([]*db.RevokedCertificateInfo, 0, len(serials))
	certs := make([]*x509.Certificate, 0, len(serials))
	var alreadyRevoked int
	for _, serial := range serials {
		cert, err := a.db.GetCertificate(serial)
		if err != nil {
			return nil, errs.BadRequest("certificate with serial number %s was not found", serial)
		}
		if !now.Before(cert.NotAfter) {
			return nil, errs.BadRequest("certificate with serial number %s has already expired; natural expiry is sufficient", serial)
		}

		revoked, err := a.IsRevoked(serial)
		if err != nil {
			return nil, errs.Wrap(http.StatusInternalServerError, err, "authority.RevokeBatch; error checking revocation status")
		}
		if revoked {
			alreadyRevoked++
			continue
		}

		certs = append(certs, cert)
		records = append(records, &db.RevokedCertificateInfo{
			Serial:     serial,
			ReasonCode: opts.ReasonCode,
			Reason:     opts.Reason,
			RevokedAt:  now,
			ExpiresAt:  cert.NotAfter,
		})
	}

	if len(records) == 0 {
		return &RevokeBatchResult{
			Status:         "ok",
			AlreadyRevoked: alreadyRevoked,
			Confirmation:   confirmation,
		}, nil
	}

	batchRevoker, err := a.batchRevoker()
	if err != nil {
		return nil, errs.Wrap(http.StatusNotImplemented, err, "authority.RevokeBatch")
	}

	// Do the CAS operation before touching the local revocation table. The
	// default SoftCAS is a no-op; linked CAS implementations that do not support
	// batch revocation must fail before any local records are written.
	for i, cert := range certs {
		_, err := a.x509CAService.RevokeCertificate(&casapi.RevokeCertificateRequest{
			Certificate:  cert,
			SerialNumber: records[i].Serial,
			Reason:       opts.Reason,
			ReasonCode:   opts.ReasonCode,
			PassiveOnly:  true,
		})
		if err != nil {
			return nil, errs.Wrap(http.StatusInternalServerError, err, "authority.RevokeBatch; CAS revocation failed")
		}
	}

	if err := batchRevoker.RevokeBatch(records); err != nil {
		return nil, errs.Wrap(http.StatusInternalServerError, err, "authority.RevokeBatch")
	}

	if a.config.CRL.IsEnabled() && a.config.CRL.GenerateOnRevoke {
		if err := a.GenerateCertificateRevocationList(); err != nil {
			return nil, errs.Wrap(http.StatusInternalServerError, err, "authority.RevokeBatch; error generating CRL")
		}
	}

	log.Printf("revocation: batch committed: total=%d affected=%d already_revoked=%d confirmation=%s",
		len(serials), len(records), alreadyRevoked, confirmation)

	return &RevokeBatchResult{
		Status:         "ok",
		Revoked:        len(records),
		AlreadyRevoked: alreadyRevoked,
		Confirmation:   confirmation,
	}, nil
}

type batchRevoker interface {
	RevokeBatch([]*db.RevokedCertificateInfo) error
}

func (a *Authority) batchRevoker() (batchRevoker, error) {
	if a.adminDB != nil {
		if revoker, ok := a.adminDB.(batchRevoker); ok {
			return revoker, nil
		}
		// A linked/remote admin database cannot safely fall back to the local
		// revocation table. Local admin databases can, matching Revoke's
		// existing fallback behavior.
		if _, remote := a.adminDB.(interface {
			IsRevoked(string) (bool, error)
		}); remote {
			return nil, errors.New("remote persistence layer does not support atomic batch revocation")
		}
	}
	if revoker, ok := a.db.(batchRevoker); ok {
		return revoker, nil
	}
	return nil, errors.New("persistence layer does not support atomic batch revocation")
}

func validateRevokeBatchOptions(opts *RevokeBatchOptions) ([]string, error) {
	if opts == nil {
		return nil, errs.BadRequest("batch revocation options are required")
	}
	if len(opts.Serials) == 0 {
		return nil, errs.BadRequest("at least one certificate serial is required")
	}
	if len(opts.Serials) > maxRevokeBatchSize {
		return nil, errs.BadRequest("batch revocation is limited to %d certificates", maxRevokeBatchSize)
	}
	if opts.ReasonCode < ocsp.Unspecified || opts.ReasonCode > ocsp.AACompromise {
		return nil, errs.BadRequest("reasonCode out of bounds")
	}

	seen := make(map[string]struct{}, len(opts.Serials))
	serials := make([]string, 0, len(opts.Serials))
	for _, input := range opts.Serials {
		sn, ok := new(big.Int).SetString(input, 0)
		if !ok {
			return nil, errs.BadRequest("'%s' is not a valid serial number", input)
		}
		serial := sn.String()
		if _, ok := seen[serial]; ok {
			return nil, errs.BadRequest("serial number %s is duplicated in batch", serial)
		}
		seen[serial] = struct{}{}
		serials = append(serials, serial)
	}
	sort.Strings(serials)
	return serials, nil
}

func revokeBatchConfirmation(serials []string, reasonCode int, reason string) string {
	h := sha256.New()
	for _, serial := range serials {
		fmt.Fprintf(h, "%s\x00", serial)
	}
	fmt.Fprintf(h, "%d\x00%s", reasonCode, reason)
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// GetRevocationSnapshot returns the current short-lived certificate
// revocation view. The feed intentionally excludes records whose certificates
// have already expired.
func (a *Authority) GetRevocationSnapshot(now time.Time) (*revocation.Snapshot, error) {
	cfg := a.config.Revocation
	if !cfg.IsEnabled() {
		return nil, errs.Wrap(http.StatusNotFound, errors.New("revocation feed is not enabled"), "authority.GetRevocationSnapshot")
	}

	lister, ok := a.db.(interface {
		GetRevokedCertificates() (*[]db.RevokedCertificateInfo, error)
	})
	if !ok {
		return nil, errs.Wrap(http.StatusNotImplemented, errors.New("database does not support revocation snapshots"), "authority.GetRevocationSnapshot")
	}

	list, err := lister.GetRevokedCertificates()
	if err != nil {
		return nil, errs.Wrap(http.StatusInternalServerError, err, "authority.GetRevocationSnapshot")
	}

	now = now.UTC().Truncate(time.Second)
	entries := make([]revocation.Entry, 0, len(*list))
	for _, rci := range *list {
		if !rci.ExpiresAt.IsZero() && !now.Before(rci.ExpiresAt) {
			continue
		}
		var expiresAt *time.Time
		if !rci.ExpiresAt.IsZero() {
			t := rci.ExpiresAt.UTC()
			expiresAt = &t
		}
		entries = append(entries, revocation.Entry{
			Serial:     rci.Serial,
			RevokedAt:  rci.RevokedAt.UTC(),
			ExpiresAt:  expiresAt,
			ReasonCode: rci.ReasonCode,
			Reason:     rci.Reason,
		})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Serial < entries[j].Serial
	})

	policy := cfg.FailurePolicy
	if policy == "" {
		policy = config.DefaultRevocationFailurePolicy
	}
	snapshot := &revocation.Snapshot{
		GeneratedAt:   now,
		NextUpdate:    now.Add(cfg.PollInterval()),
		CacheDuration: int64(cfg.CacheTTL() / time.Second),
		FailurePolicy: policy,
		Revocations:   entries,
	}
	snapshot.Version = snapshot.ComputeETag()
	return snapshot, nil
}

// CleanupExpiredRevocations removes records after both the certificate and the
// configured retention grace period have expired.
func (a *Authority) CleanupExpiredRevocations(now time.Time) (int, error) {
	cfg := a.config.Revocation
	if !cfg.IsEnabled() {
		return 0, nil
	}
	cleaner, ok := a.db.(interface {
		DeleteExpiredRevocations(time.Time) (int, error)
	})
	if !ok {
		return 0, nil
	}
	deleted, err := cleaner.DeleteExpiredRevocations(cfg.CleanupCutoff(now.UTC()))
	if err != nil {
		return 0, err
	}
	if deleted > 0 {
		log.Printf("revocation: cleaned up %d expired records", deleted)
	}
	return deleted, nil
}

// CleanupExpiredRevocations background maintenance is started by the
// authority when the revocation feed is enabled.
func (a *Authority) startRevocationCleanup() error {
	if !a.config.Revocation.IsEnabled() {
		return nil
	}
	if _, ok := a.db.(interface {
		DeleteExpiredRevocations(time.Time) (int, error)
	}); !ok {
		return errors.New("revocation feed enabled, but database does not support expired record cleanup")
	}

	if _, err := a.CleanupExpiredRevocations(time.Now()); err != nil {
		return errors.Wrap(err, "could not clean expired revocations")
	}

	a.revocationStopper = make(chan struct{}, 1)
	a.revocationTicker = time.NewTicker(a.config.Revocation.CleanupEvery())
	go func() {
		for {
			select {
			case <-a.revocationTicker.C:
				if _, err := a.CleanupExpiredRevocations(time.Now()); err != nil {
					log.Printf("revocation: cleanup failed: %v", err)
				}
			case <-a.revocationStopper:
				return
			}
		}
	}()
	return nil
}
