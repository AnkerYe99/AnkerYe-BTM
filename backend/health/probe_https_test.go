package health

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"ankerye-flow/model"
)

func makeTLSOrigin(t *testing.T, dnsName string) (*httptest.Server, string) {
	t.Helper()
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "BTM health test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: dnsName}, DNSNames: []string{dnsName},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(leafKey)})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	return srv, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
}

func serverFromListener(t *testing.T, addr net.Addr) model.Server {
	t.Helper()
	host, portText, err := net.SplitHostPort(addr.String())
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(portText)
	return model.Server{Address: host, Port: port, State: "up"}
}

func TestHTTPSProbeUsesSNIAndCustomCAWithoutTCPFallback(t *testing.T) {
	srv, caPEM := makeTLSOrigin(t, "origin.example.invalid")
	defer srv.Close()
	s := serverFromListener(t, srv.Listener.Addr())
	r := &model.Rule{
		Protocol: "http", ServerName: "api.example.invalid", HCTimeout: 2, HCPath: "/",
		UpstreamProtocol: "https", ProxySSLName: "origin.example.invalid", ProxySSLVerify: 1,
		ProxySSLTrustedCAPEM: caPEM, ProxySSLVerifyDepth: 5,
	}
	if got := Probe(&s, r); !got.OK {
		t.Fatalf("valid HTTPS origin marked down: %s", got.Err)
	}
	r.ProxySSLName = "wrong.example.invalid"
	if got := Probe(&s, r); got.OK {
		t.Fatal("wrong SNI/name was hidden by TCP fallback")
	}
	r.ProxySSLVerify = 0
	if got := Probe(&s, r); !got.OK {
		t.Fatalf("explicit verify=off did not work in isolated test: %s", got.Err)
	}
}
