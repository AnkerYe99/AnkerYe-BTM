package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"ankerye-flow/config"
	"ankerye-flow/db"
)

func TestNewSlaveNormalizesOldWireFormat(t *testing.T) {
	var r syncRule
	if err := json.Unmarshal([]byte(`{
		"id":7,"name":"legacy","protocol":"http","listen_port":80,
		"listen_stack":"both","server_name":"api.example.invalid","lb_method":"round_robin",
		"status":1,"servers":[{"address":"192.0.2.10","port":8080,"weight":1,"state":"up"}]
	}`), &r); err != nil {
		t.Fatal(err)
	}
	if err := normalizeSyncRule(&r); err != nil {
		t.Fatal(err)
	}
	if r.UpstreamProtocol != "http" || r.ProxySSLVerify == nil || *r.ProxySSLVerify != 1 ||
		r.ProxySSLVerifyDepth == nil || *r.ProxySSLVerifyDepth != 5 ||
		r.ProxyReadTimeout == nil || *r.ProxyReadTimeout != 60 {
		t.Fatalf("old wire defaults not normalized: %+v", r)
	}
}

func TestUpsertRulesPersistsHTTPSUpstreamFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sync.db")
	if err := db.Init(path); err != nil {
		t.Fatal(err)
	}
	defer db.DB.Close()
	verify, depth, timeout := int64(1), int64(5), int64(660)
	r := syncRule{
		ID: 9, Name: "https", Protocol: "http", ListenPort: 443, ListenStack: "both",
		ServerName: "api.example.invalid", LbMethod: "round_robin", Status: 1,
		UpstreamProtocol: "https", ProxySSLName: "origin.example.invalid",
		ProxySSLVerify: &verify, ProxySSLVerifyDepth: &depth, ProxyReadTimeout: &timeout,
		Servers: []syncServer{{Address: "192.0.2.20", Port: 10443, Weight: 1, State: "up"}},
	}
	if err := upsertRules([]syncRule{r}); err != nil {
		t.Fatal(err)
	}
	var proto, name string
	var gotVerify, gotDepth, gotTimeout int64
	if err := db.DB.QueryRow(`SELECT upstream_protocol,proxy_ssl_name,proxy_ssl_verify,
		proxy_ssl_verify_depth,proxy_read_timeout FROM rules WHERE id=9`).
		Scan(&proto, &name, &gotVerify, &gotDepth, &gotTimeout); err != nil {
		t.Fatal(err)
	}
	if proto != "https" || name != "origin.example.invalid" || gotVerify != 1 || gotDepth != 5 || gotTimeout != 660 {
		t.Fatalf("persisted values differ: %s %s %d %d %d", proto, name, gotVerify, gotDepth, gotTimeout)
	}
}

func setupSyncApplyTest(t *testing.T, nginxExit int) (string, string) {
	t.Helper()
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
	if err := db.Init(filepath.Join(root, "sync-apply.db")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.DB.Close() })
	if _, err := db.DB.Exec(`INSERT INTO rules(id,name,protocol,listen_port,listen_stack,server_name,lb_method,status)
		VALUES(7,'old','http',80,'v4','api.example.invalid','round_robin',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstream_servers(rule_id,address,port,weight,state)
		VALUES(7,'192.0.2.10',8080,1,'up')`); err != nil {
		t.Fatal(err)
	}
	confPath := filepath.Join(config.Global.Nginx.ConfDir, "7-http.conf")
	caPath := UpstreamCAPath(7)
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
	script := []byte("#!/bin/sh\nexit " + string(rune('0'+nginxExit)) + "\n")
	if err := os.WriteFile(filepath.Join(fakeBin, "nginx"), script, 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fakeBin+":"+os.Getenv("PATH"))
	return confPath, caPath
}

func assertSyncApplyOldState(t *testing.T, confPath, caPath string) {
	t.Helper()
	for path, want := range map[string]string{confPath: "old-conf\n", caPath: "old-ca\n"} {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != want {
			t.Fatalf("%s not restored: %q", path, got)
		}
	}
	var name string
	if err := db.DB.QueryRow(`SELECT name FROM rules WHERE id=7`).Scan(&name); err != nil {
		t.Fatal(err)
	}
	if name != "old" {
		t.Fatalf("database was not rolled back: name=%q", name)
	}
}

func TestApplyRulesFullRestoresFilesWhenNginxTestFails(t *testing.T) {
	confPath, caPath := setupSyncApplyTest(t, 1)
	verify, depth, timeout := int64(1), int64(5), int64(660)
	result := syncRulesResp{}
	result.Data.NginxConfigs = map[string]string{"7-http.conf": "new-conf\n"}
	result.Data.Rules = []syncRule{{
		ID: 7, Name: "new", Protocol: "http", ListenPort: 80, ListenStack: "v4",
		ServerName: "api.example.invalid", LbMethod: "round_robin", Status: 1,
		UpstreamProtocol: "https", ProxySSLName: "origin.example.invalid",
		ProxySSLVerify: &verify, ProxySSLTrustedCAPEM: testCAPEM(t),
		ProxySSLVerifyDepth: &depth, ProxyReadTimeout: &timeout,
		Servers: []syncServer{{Address: "192.0.2.20", Port: 8443, Weight: 1, State: "up"}},
	}}
	if err := applyRulesFull(result); err == nil {
		t.Fatal("applyRulesFull unexpectedly succeeded")
	}
	assertSyncApplyOldState(t, confPath, caPath)
}

func TestApplyRulesFullRollsBackDatabaseOnSQLFailure(t *testing.T) {
	confPath, caPath := setupSyncApplyTest(t, 0)
	verify, depth, timeout := int64(1), int64(5), int64(60)
	result := syncRulesResp{}
	result.Data.NginxConfigs = map[string]string{"7-http.conf": "new-conf\n"}
	result.Data.Rules = []syncRule{{
		ID: 7, Name: "new", Protocol: "http", ListenPort: 80, ListenStack: "v4",
		ServerName: "api.example.invalid", LbMethod: "round_robin", Status: 1,
		UpstreamProtocol: "http", ProxySSLVerify: &verify,
		ProxySSLVerifyDepth: &depth, ProxyReadTimeout: &timeout,
		Servers: []syncServer{{Address: "192.0.2.20", Port: 8080, Weight: 1, State: "invalid"}},
	}}
	if err := applyRulesFull(result); err == nil {
		t.Fatal("applyRulesFull unexpectedly accepted invalid server state")
	}
	assertSyncApplyOldState(t, confPath, caPath)
}
