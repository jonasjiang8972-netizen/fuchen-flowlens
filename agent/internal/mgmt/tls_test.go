package mgmt

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jonasjiang8972-netizen/fuchen-flowlens/agent/internal/config"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/shared"
)

type testPKI struct {
	caCert *x509.Certificate
	caKey  *ecdsa.PrivateKey
	caPEM  []byte
}

func newPKI(t *testing.T, name string) *testPKI {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &testPKI{caCert: cert, caKey: key, caPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func (p *testPKI) issue(t *testing.T, cn string, usage x509.ExtKeyUsage) (certPEM, keyPEM []byte) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, DNSNames: []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.caCert, &key.PublicKey, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
}

func write(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// mtlsServer requires a client certificate signed by pki.
func mtlsServer(t *testing.T, pki *testPKI) *httptest.Server {
	t.Helper()
	certPEM, keyPEM := pki.issue(t, "platform", x509.ExtKeyUsageServerAuth)
	serverCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pki.caPEM)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		w.Write([]byte(`{"accepted":1}`))
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert}, ClientCAs: pool,
		ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func TestMutualTLS(t *testing.T) {
	pki := newPKI(t, "flowlens-ca")
	srv := mtlsServer(t, pki)
	dir := t.TempDir()
	caPath := write(t, dir, "ca.pem", pki.caPEM)
	cCert, cKey := pki.issue(t, "agent-01", x509.ExtKeyUsageClientAuth)
	certPath, keyPath := write(t, dir, "agent.pem", cCert), write(t, dir, "agent.key", cKey)
	endpoint := strings.TrimPrefix(srv.URL, "https://")
	events := make([]shared.APIEvent, 1)

	c, err := NewClient(config.ManagementConfig{PlatformEndpoint: endpoint, UseTLS: true,
		TLSCAPath: caPath, TLSCertPath: certPath, TLSKeyPath: keyPath})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.SendEvents(context.Background(), events); err != nil {
		t.Fatalf("with client certificate: %v", err)
	}

	noCert, _ := NewClient(config.ManagementConfig{PlatformEndpoint: endpoint, UseTLS: true, TLSCAPath: caPath})
	if _, err := noCert.SendEvents(context.Background(), events); err == nil {
		t.Fatal("connected without a client certificate")
	}

	other := newPKI(t, "rogue-ca")
	roguePath := write(t, dir, "rogue.pem", other.caPEM)
	wrongCA, _ := NewClient(config.ManagementConfig{PlatformEndpoint: endpoint, UseTLS: true,
		TLSCAPath: roguePath, TLSCertPath: certPath, TLSKeyPath: keyPath})
	if _, err := wrongCA.SendEvents(context.Background(), events); err == nil {
		t.Fatal("trusted a platform certificate from an unknown CA")
	}
}

func TestNewClientRejectsBadTLSFiles(t *testing.T) {
	dir := t.TempDir()
	junk := write(t, dir, "junk.pem", []byte("not a certificate"))
	for _, cfg := range []config.ManagementConfig{
		{UseTLS: true, TLSCAPath: filepath.Join(dir, "missing.pem")},
		{UseTLS: true, TLSCAPath: junk},
		{UseTLS: true, TLSCertPath: junk, TLSKeyPath: junk},
	} {
		if _, err := NewClient(cfg); err == nil {
			t.Errorf("accepted bad TLS config %+v", cfg)
		}
	}
}
