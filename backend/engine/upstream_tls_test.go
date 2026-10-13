package engine

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ankerye-flow/config"
	"ankerye-flow/db"
	"ankerye-flow/model"
)

func testCAPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "BTM Test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func baseHTTPRule() *model.Rule {
	return &model.Rule{
		ID: 42, Name: "synthetic", Protocol: "http", ListenPort: 80, ListenStack: "v4",
		ServerName: "api.example.invalid", LBMethod: "round_robin", LogMaxSize: "5M",
		UpstreamProtocol: "http", ProxySSLVerify: 1, ProxySSLVerifyDepth: 5,
		ProxyReadTimeout: 60,
		Servers:          []model.Server{{Address: "192.0.2.10", Port: 8080, Weight: 1, State: "up"}},
	}
}

func TestLegacyProxyBlockIsByteFrozen(t *testing.T) {
	want := `    location / {
        if ($__nf_block) {
            return 444;
        }
        proxy_pass http://nf_42;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_connect_timeout 5s;
        proxy_read_timeout 60s;
    }
`
	got, err := proxyBlock(baseHTTPRule())
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("legacy proxy block changed\nwant:\n%s\ngot:\n%s", want, got)
	}
}

func TestRenderHTTPSUpstream(t *testing.T) {
	config.Global.Nginx.CertDir = "/etc/nginx/certs"
	config.Global.Nginx.LogDir = "/var/log/AnkerYe-BTM"
	r := baseHTTPRule()
	r.UpstreamProtocol = "https"
	r.ProxySSLName = "origin.example.invalid"
	r.ProxySSLTrustedCAPEM = testCAPEM(t)
	r.ProxyReadTimeout = 660
	got, err := RenderRule(r)
	if err != nil {
		t.Fatal(err)
	}
	wantLines := []string{
		"proxy_pass https://nf_42;",
		"proxy_read_timeout 660s;",
		"proxy_ssl_server_name on;",
		"proxy_ssl_name origin.example.invalid;",
		"proxy_ssl_protocols TLSv1.2 TLSv1.3;",
		"proxy_ssl_verify on;",
		"proxy_ssl_trusted_certificate /etc/nginx/certs/_upstream_ca/rule-42.pem;",
		"proxy_ssl_verify_depth 5;",
	}
	last := -1
	for _, line := range wantLines {
		idx := strings.Index(got, line)
		if idx < 0 {
			t.Fatalf("missing %q in:\n%s", line, got)
		}
		if idx <= last {
			t.Fatalf("directive order changed at %q", line)
		}
		last = idx
	}
}

func TestRenderHTTPSVerifyOffOmitsTrustedCA(t *testing.T) {
	r := baseHTTPRule()
	r.UpstreamProtocol = "https"
	r.ProxySSLVerify = 0
	got, err := RenderRule(r)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "proxy_ssl_verify off;") || strings.Contains(got, "proxy_ssl_trusted_certificate") {
		t.Fatalf("verify=off output invalid:\n%s", got)
	}
}

func TestRenderHTTPWithCustomReadTimeoutHasNoTLSDirectives(t *testing.T) {
	r := baseHTTPRule()
	r.ProxyReadTimeout = 660
	got, err := RenderRule(r)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "proxy_pass http://nf_42;") || !strings.Contains(got, "proxy_read_timeout 660s;") {
		t.Fatalf("custom HTTP timeout missing:\n%s", got)
	}
	if strings.Contains(got, "proxy_ssl_") {
		t.Fatalf("HTTP upstream unexpectedly emitted TLS directives:\n%s", got)
	}
}

func TestRenderHTTPSWithSystemCA(t *testing.T) {
	r := baseHTTPRule()
	r.UpstreamProtocol = "https"
	got, err := RenderRule(r)
	if err != nil {
		t.Fatal(err)
	}
	want := "proxy_ssl_trusted_certificate " + SystemTrustedCAPath + ";"
	if !strings.Contains(got, want) {
		t.Fatalf("system CA directive missing: %s\n%s", want, got)
	}
}

func TestTrustedCAPEMValidation(t *testing.T) {
	ca := testCAPEM(t)
	got, err := NormalizeTrustedCAPEM(strings.ReplaceAll(strings.TrimSuffix(ca, "\n"), "\n", "\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, "\r") || !strings.HasSuffix(got, "\n") {
		t.Fatalf("CA was not normalized")
	}
	private := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not-a-key")})
	if _, err := NormalizeTrustedCAPEM(string(private)); err == nil {
		t.Fatal("private key PEM was accepted")
	}
	if _, err := NormalizeTrustedCAPEM(ca + "garbage"); err == nil {
		t.Fatal("trailing garbage was accepted")
	}
	if _, err := NormalizeTrustedCAPEM(strings.Repeat("x", MaxProxyTrustedCAPEMBytes+1)); err == nil {
		t.Fatal("oversized CA bundle was accepted")
	}
}

func TestApplyRuleRestoresConfigAndCAWhenNginxTestFails(t *testing.T) {
	oldConfig := config.Global
	t.Cleanup(func() { config.Global = oldConfig })
	root := t.TempDir()
	config.Global.Nginx.ConfDir = filepath.Join(root, "conf")
	config.Global.Nginx.CertDir = filepath.Join(root, "certs")
	config.Global.Nginx.LogDir = filepath.Join(root, "logs")
	config.Global.Nginx.LogrotateDir = filepath.Join(root, "logrotate")
	for _, dir := range []string{config.Global.Nginx.ConfDir, config.Global.Nginx.CertDir, config.Global.Nginx.LogDir, config.Global.Nginx.LogrotateDir} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Init(filepath.Join(root, "test.db")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.DB.Close() })
	ca := testCAPEM(t)
	if _, err := db.DB.Exec(`INSERT INTO rules(id,name,protocol,listen_port,listen_stack,server_name,lb_method,
		upstream_protocol,proxy_ssl_name,proxy_ssl_verify,proxy_ssl_trusted_ca_pem,
		proxy_ssl_verify_depth,proxy_read_timeout,status)
		VALUES(42,'new','http',80,'v4','api.example.invalid','round_robin','https',
		'origin.example.invalid',1,?,5,660,1)`, ca); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstream_servers(rule_id,address,port,weight,state)
		VALUES(42,'192.0.2.10',8443,1,'up')`); err != nil {
		t.Fatal(err)
	}
	confPath := filepath.Join(config.Global.Nginx.ConfDir, "42-http.conf")
	caPath := UpstreamCAPath(42)
	if err := os.MkdirAll(filepath.Dir(caPath), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(confPath, []byte("old-conf\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caPath, []byte("old-ca\n"), 0644); err != nil {
		t.Fatal(err)
	}
	fakeBin := filepath.Join(root, "bin")
	if err := os.MkdirAll(fakeBin, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fakeBin, "nginx"), []byte("#!/bin/sh\nexit 1\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fakeBin+":"+os.Getenv("PATH"))
	if err := ApplyRule(42); err == nil {
		t.Fatal("ApplyRule unexpectedly succeeded")
	}
	for path, want := range map[string]string{confPath: "old-conf\n", caPath: "old-ca\n"} {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != want {
			t.Fatalf("%s not restored: %q", path, got)
		}
	}
}

func TestProxySSLNameValidationAndDerivation(t *testing.T) {
	got, err := ResolveProxySSLName("", "_ *.example.invalid API.Example.Invalid")
	if err != nil || got != "api.example.invalid" {
		t.Fatalf("derive got=%q err=%v", got, err)
	}
	for _, bad := range []string{"*.example.invalid", "bad_name.invalid", "192.0.2.1", "$host", "a;include"} {
		if _, err := NormalizeProxySSLName(bad); err == nil {
			t.Errorf("accepted invalid proxy_ssl_name %q", bad)
		}
	}
}

func TestRuleFingerprintKeepsLegacyLineAndAddsU1(t *testing.T) {
	r := RuleFP{
		ID: 1, Name: "r", Protocol: "http", ListenPort: 80, ListenStack: "both",
		ServerName: "a.example.invalid", LBMethod: "round_robin", HCPath: "/",
		LogMaxSize: "5M", CaptureMaxSize: "5M", IPACLMode: "off",
		UpstreamProtocol: "http", ProxySSLVerify: 1, ProxySSLVerifyDepth: 5, ProxyReadTimeout: 60,
	}
	var legacy bytes.Buffer
	WriteRuleFP(&legacy, r)
	if strings.Contains(legacy.String(), "U1:") {
		t.Fatalf("default fields changed legacy fingerprint: %q", legacy.String())
	}
	r.ProxyReadTimeout = 660
	var changed bytes.Buffer
	WriteRuleFP(&changed, r)
	if !strings.HasPrefix(changed.String(), legacy.String()) || !strings.Contains(changed.String(), "U1:1|") {
		t.Fatalf("non-default fields did not append U1 without changing R line: %q", changed.String())
	}
}
