package rotation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// testCA bundles a generated root with its signer so tests can build issuers.
type testCA struct {
	root     *x509.Certificate
	rootKey  *ecdsa.PrivateKey
	inter    *x509.Certificate
	interKey *ecdsa.PrivateKey
	serial   int64
}

func newSerial() *big.Int {
	return big.NewInt(time.Now().UnixNano())
}

// newTestRootCA creates a self-signed root and an intermediate issued by it.
func newTestRootCA(cn string) (*testCA, error) {
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	// SubjectKeyId left nil: Go derives it (RFC 5280 method 1) when creating the
	// certificate, so both root and intermediate carry a usable SKI.
	rootTpl := &x509.Certificate{
		SerialNumber:          newSerial(),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTpl, rootTpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, err
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		return nil, err
	}

	interKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	interTpl := &x509.Certificate{
		SerialNumber:          newSerial(),
		Subject:               pkix.Name{CommonName: cn + "-intermediate"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	interDER, err := x509.CreateCertificate(rand.Reader, interTpl, root, &interKey.PublicKey, rootKey)
	if err != nil {
		return nil, err
	}
	inter, err := x509.ParseCertificate(interDER)
	if err != nil {
		return nil, err
	}
	return &testCA{root: root, rootKey: rootKey, inter: inter, interKey: interKey}, nil
}

func (ca *testCA) issuer() Issuer {
	return Issuer{Signer: ca.interKey, Chain: []*x509.Certificate{ca.inter, ca.root}}
}

// issueLeaf signs a leaf directly using this CA's intermediate (independent of
// the manager) so tests can construct arbitrary chain scenarios.
func (ca *testCA) issueLeaf(dns string, notBefore, notAfter time.Time) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	ca.serial++
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(ca.serial),
		Subject:      pkix.Name{CommonName: dns},
		DNSNames:     []string{dns},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.inter, &key.PublicKey, ca.interKey)
	if err != nil {
		return nil, nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return leaf, key, nil
}

// issueLeafFromRoot signs a leaf directly with the root key (no intermediate),
// producing a leaf whose AKI names the root SKI. Used to exercise the "root
// known but issuer chain not registered" broken-chain path.
func (ca *testCA) issueLeafFromRoot(dns string, notBefore, notAfter time.Time) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tpl := &x509.Certificate{
		SerialNumber: newSerial(),
		Subject:      pkix.Name{CommonName: dns},
		DNSNames:     []string{dns},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.root, &key.PublicKey, ca.rootKey)
	if err != nil {
		return nil, nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return leaf, key, nil
}

// serverCert builds a ServerCert from one of this CA's leaves.
func serverCertFrom(leaf *x509.Certificate, key *ecdsa.PrivateKey, ca *testCA, rootID string) *ServerCert {
	return &ServerCert{
		Certificate: leaf,
		TLSCert:     tls.Certificate{Certificate: [][]byte{leaf.Raw, ca.inter.Raw, ca.root.Raw}, PrivateKey: key},
		Chain:       []*x509.Certificate{leaf, ca.inter, ca.root},
		RootID:      rootID,
	}
}

func rootConfig(ca *testCA, id string, state State, nb, na time.Time) RootConfig {
	return RootConfig{ID: id, Certificate: ca.root, State: state, NotBefore: nb, NotAfter: na}
}

// mustLeafKey generates a fresh leaf key, failing the test on error.
func mustLeafKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	return key
}

// leafTemplate builds a valid leaf template for engine-driven signing.
func leafTemplate(dns string) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: newSerial(),
		Subject:      pkix.Name{CommonName: dns},
		DNSNames:     []string{dns},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
}

// itoa is a tiny allocation-free int-to-string for test CRL bytes.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// errBoom is the sentinel failure injected into CRL generation tests.
var errBoom = &testError{"boom"}

type testError struct{ msg string }

func (e *testError) Error() string { return e.msg }
