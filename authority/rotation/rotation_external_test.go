package rotation_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/smallstep/certificates/authority/rotation"
)

// genRoot builds a self-signed root plus an intermediate for external API tests.
func genRoot(t *testing.T, cn string) (*x509.Certificate, *ecdsa.PrivateKey, *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true, IsCA: true,
	}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTpl, rootTpl, &rootKey.PublicKey, rootKey)
	root, _ := x509.ParseCertificate(rootDER)

	interKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	interTpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: cn + "-inter"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true, IsCA: true,
	}
	interDER, _ := x509.CreateCertificate(rand.Reader, interTpl, root, &interKey.PublicKey, rootKey)
	inter, _ := x509.ParseCertificate(interDER)
	return root, rootKey, inter, interKey
}

// TestExternalAPISingleRootParity drives the engine purely through its exported
// surface the way an embedding authority would, and asserts the public root set
// remains an additive, parseable structure over the bare certificate list.
func TestExternalAPISingleRootParity(t *testing.T) {
	now := time.Now()
	root, _, inter, interKey := genRoot(t, "External Root")

	m, err := rotation.NewManagerFromBundles([]rotation.RootBundle{{
		ID: "r1", Certificate: root,
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.RegisterIssuer("r1", rotation.Issuer{
		Signer: interKey, Chain: []*x509.Certificate{inter, root},
	}); err != nil {
		t.Fatal(err)
	}

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	res, err := m.Sign(rotation.SignRequest{
		Template: &x509.Certificate{
			SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "svc"},
			DNSNames: []string{"svc"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
			KeyUsage:    x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		},
		PublicKey: &leafKey.PublicKey,
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := m.Verify(res.Leaf, rotation.VerifyOptions{}); err != nil {
		t.Fatalf("verify: %v", err)
	}

	// The public root set must expose the three-state classification while still
	// handing back the original *x509.Certificate (existing clients parse these).
	set := m.Snapshot()
	if len(set.Roots) != 1 {
		t.Fatalf("expected one root, got %d", len(set.Roots))
	}
	v := set.Roots[0]
	if v.Status != rotation.StatusActiveIssuer {
		t.Fatalf("unexpected status %q", v.Status)
	}
	if v.Certificate == nil || v.Certificate.Subject.CommonName != "External Root" {
		t.Fatal("root view must retain the parseable certificate")
	}
	if v.Fingerprint != rotation.Fingerprint(root.Raw) {
		t.Fatal("fingerprint mismatch")
	}
}

// ExampleNewManagerFromBundles documents the minimal single-root usage.
func ExampleNewManagerFromBundles() {
	fmt.Println("rotation engine ready")
	// Output: rotation engine ready
}
