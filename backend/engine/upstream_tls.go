package engine

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"ankerye-flow/config"
	"ankerye-flow/model"
)

const (
	DefaultUpstreamProtocol    = "http"
	DefaultProxySSLVerify      = 1
	DefaultProxySSLVerifyDepth = 5
	DefaultProxyReadTimeout    = 60
	MaxProxyTrustedCAPEMBytes  = 256 * 1024
	SystemTrustedCAPath        = "/etc/ssl/certs/ca-certificates.crt"
)

var dnsLabelRE = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// NormalizeTrustedCAPEM validates a public CA bundle and returns its stable wire form.
// It never accepts private keys or arbitrary PEM blocks.
func NormalizeTrustedCAPEM(value string) (string, error) {
	value = strings.ReplaceAll(value, "\r\n", "\n")
	value = strings.ReplaceAll(value, "\r", "\n")
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}
	if len(value) > MaxProxyTrustedCAPEMBytes {
		return "", fmt.Errorf("proxy_ssl_trusted_ca_pem 超过 256 KiB")
	}

	rest := []byte(value)
	count := 0
	for len(strings.TrimSpace(string(rest))) > 0 {
		block, next := pem.Decode(rest)
		if block == nil {
			return "", fmt.Errorf("proxy_ssl_trusted_ca_pem 只能包含 CERTIFICATE PEM")
		}
		if block.Type != "CERTIFICATE" {
			return "", fmt.Errorf("proxy_ssl_trusted_ca_pem 不允许 %s PEM", block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return "", fmt.Errorf("proxy_ssl_trusted_ca_pem 含无效证书: %w", err)
		}
		if !cert.IsCA {
			return "", fmt.Errorf("proxy_ssl_trusted_ca_pem 只能包含 CA 证书")
		}
		count++
		rest = next
	}
	if count == 0 {
		return "", fmt.Errorf("proxy_ssl_trusted_ca_pem 未包含证书")
	}
	return value + "\n", nil
}

func normalizeDNSName(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "", fmt.Errorf("名称不能为空")
	}
	if len(value) > 253 || strings.HasSuffix(value, ".") || strings.ContainsAny(value, "_*$/;\\\t\r\n ") {
		return "", fmt.Errorf("必须是 ASCII DNS hostname")
	}
	if net.ParseIP(value) != nil {
		return "", fmt.Errorf("必须是 ASCII DNS hostname")
	}
	for _, r := range value {
		if r > 127 {
			return "", fmt.Errorf("必须是 ASCII DNS hostname")
		}
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || !dnsLabelRE.MatchString(label) {
			return "", fmt.Errorf("必须是 ASCII DNS hostname")
		}
	}
	return value, nil
}

// NormalizeProxySSLName validates an explicitly configured SNI name.
func NormalizeProxySSLName(value string) (string, error) {
	return normalizeDNSName(value)
}

// ResolveProxySSLName returns the explicit value, or the first exact DNS name in server_name.
func ResolveProxySSLName(explicit, serverName string) (string, error) {
	if strings.TrimSpace(explicit) != "" {
		return normalizeDNSName(explicit)
	}
	for _, candidate := range strings.Fields(serverName) {
		if candidate == "_" || strings.HasPrefix(candidate, "*") || strings.HasPrefix(candidate, "~") || strings.Contains(candidate, "$") {
			continue
		}
		if name, err := normalizeDNSName(candidate); err == nil {
			return name, nil
		}
	}
	return "", fmt.Errorf("HTTPS 回源无法从 server_name 推导 proxy_ssl_name，请显式填写")
}

func NormalizeRuleUpstreamDefaults(r *model.Rule) {
	if r.UpstreamProtocol == "" {
		r.UpstreamProtocol = DefaultUpstreamProtocol
	}
	if r.ProxySSLVerify != 0 && r.ProxySSLVerify != 1 {
		r.ProxySSLVerify = DefaultProxySSLVerify
	}
	if r.ProxySSLVerifyDepth == 0 {
		r.ProxySSLVerifyDepth = DefaultProxySSLVerifyDepth
	}
	if r.ProxyReadTimeout == 0 {
		r.ProxyReadTimeout = DefaultProxyReadTimeout
	}
	if r.Protocol != "http" || r.UpstreamProtocol != "https" {
		r.UpstreamProtocol = DefaultUpstreamProtocol
		r.ProxySSLName = ""
		r.ProxySSLVerify = DefaultProxySSLVerify
		r.ProxySSLTrustedCAPEM = ""
		r.ProxySSLVerifyDepth = DefaultProxySSLVerifyDepth
	}
	if r.Protocol != "http" {
		r.ProxyReadTimeout = DefaultProxyReadTimeout
	}
}

func HasNonDefaultUpstreamFields(r model.Rule) bool {
	NormalizeRuleUpstreamDefaults(&r)
	return r.UpstreamProtocol != DefaultUpstreamProtocol ||
		r.ProxySSLName != "" ||
		r.ProxySSLVerify != DefaultProxySSLVerify ||
		r.ProxySSLTrustedCAPEM != "" ||
		r.ProxySSLVerifyDepth != DefaultProxySSLVerifyDepth ||
		r.ProxyReadTimeout != DefaultProxyReadTimeout
}

func TrustedCAPEMSHA256(value string) string {
	if value == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func UpstreamCAPath(ruleID int64) string {
	return filepath.Join(config.Global.Nginx.CertDir, "_upstream_ca", fmt.Sprintf("rule-%d.pem", ruleID))
}

// SyncUpstreamCAFile atomically writes or removes only the CA file owned by this rule.
func SyncUpstreamCAFile(ruleID int64, caPEM string) error {
	path := UpstreamCAPath(ruleID)
	if caPEM == "" {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".rule-ca-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0644); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.WriteString(caPEM); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
