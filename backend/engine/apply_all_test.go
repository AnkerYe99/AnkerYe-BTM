package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"ankerye-flow/config"
	"ankerye-flow/db"
)

type applyAllTestEnv struct {
	root    string
	callLog string
}

func setupApplyAllTest(t *testing.T, nginxIsRunning bool) applyAllTestEnv {
	t.Helper()
	oldConfig := config.Global
	oldDefaults := append([]string(nil), nginxPackageDefaultPaths...)
	oldPIDPath := nginxPIDPath
	t.Cleanup(func() {
		config.Global = oldConfig
		nginxPackageDefaultPaths = oldDefaults
		nginxPIDPath = oldPIDPath
	})

	root := t.TempDir()
	config.Global.Nginx.ConfDir = filepath.Join(root, "conf")
	config.Global.Nginx.CertDir = filepath.Join(root, "certs")
	config.Global.Nginx.LogDir = filepath.Join(root, "logs")
	config.Global.Nginx.LogrotateDir = filepath.Join(root, "logrotate")
	for _, dir := range []string{
		config.Global.Nginx.ConfDir,
		config.Global.Nginx.CertDir,
		config.Global.Nginx.LogDir,
		config.Global.Nginx.LogrotateDir,
	} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
	}
	nginxPackageDefaultPaths = []string{
		filepath.Join(root, "package", "conf.d", "default.conf"),
		filepath.Join(root, "package", "sites-enabled", "default"),
	}
	nginxPIDPath = filepath.Join(root, "nginx.pid")
	if nginxIsRunning {
		if err := os.WriteFile(nginxPIDPath, []byte(fmt.Sprintf("%d\n", os.Getpid())), 0644); err != nil {
			t.Fatal(err)
		}
	}

	callLog := filepath.Join(root, "nginx-calls.log")
	fakeBin := filepath.Join(root, "bin")
	if err := os.MkdirAll(fakeBin, 0755); err != nil {
		t.Fatal(err)
	}
	script := `#!/bin/sh
case "$*" in
  "-t") echo TEST >> "$NGINX_CALL_LOG"; exit "${NGINX_TEST_EXIT:-0}" ;;
  "-s reload") echo RELOAD >> "$NGINX_CALL_LOG"; exit "${NGINX_RELOAD_EXIT:-0}" ;;
  "") echo START >> "$NGINX_CALL_LOG"; exit "${NGINX_START_EXIT:-0}" ;;
  *) echo "OTHER:$*" >> "$NGINX_CALL_LOG"; exit 0 ;;
esac
`
	if err := os.WriteFile(filepath.Join(fakeBin, "nginx"), []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fakeBin+":"+os.Getenv("PATH"))
	t.Setenv("NGINX_CALL_LOG", callLog)
	t.Setenv("NGINX_TEST_EXIT", "0")
	t.Setenv("NGINX_RELOAD_EXIT", "0")
	t.Setenv("NGINX_START_EXIT", "0")

	if err := db.Init(filepath.Join(root, "test.db")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.DB.Close() })
	if _, err := db.DB.Exec(`INSERT INTO rules(id,name,protocol,listen_port,listen_stack,
		server_name,lb_method,status) VALUES(42,'legacy','http',8080,'v4',
		'api.example.invalid','round_robin',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstream_servers(rule_id,address,port,weight,state)
		VALUES(42,'192.0.2.10',8080,1,'up')`); err != nil {
		t.Fatal(err)
	}
	return applyAllTestEnv{root: root, callLog: callLog}
}

func readNginxCalls(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "\n")
}

func clearNginxCalls(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestApplyAllNoChangeSkipsTestAndReload(t *testing.T) {
	env := setupApplyAllTest(t, true)
	if err := ApplyAll(); err != nil {
		t.Fatal(err)
	}
	clearNginxCalls(t, env.callLog)

	// Disabled-rule leftovers were not pruned by the legacy startup loop and
	// must stay outside ApplyAll's managed file set.
	disabledConf := filepath.Join(config.Global.Nginx.ConfDir, "99-http.conf")
	if err := os.WriteFile(disabledConf, []byte("disabled-leftover\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := ApplyAll(); err != nil {
		t.Fatal(err)
	}
	if calls := readNginxCalls(t, env.callLog); len(calls) != 0 {
		t.Fatalf("identical apply issued nginx commands: %v", calls)
	}
	if got, err := os.ReadFile(disabledConf); err != nil || string(got) != "disabled-leftover\n" {
		t.Fatalf("disabled rule file semantics changed: got=%q err=%v", got, err)
	}
}

func TestApplyAllChangeTestsOnceAndReloadsOnce(t *testing.T) {
	env := setupApplyAllTest(t, true)
	if err := ApplyAll(); err != nil {
		t.Fatal(err)
	}
	clearNginxCalls(t, env.callLog)
	if _, err := db.DB.Exec(`UPDATE rules SET name='changed' WHERE id=42`); err != nil {
		t.Fatal(err)
	}
	if err := ApplyAll(); err != nil {
		t.Fatal(err)
	}
	want := []string{"TEST", "RELOAD"}
	if got := readNginxCalls(t, env.callLog); !reflect.DeepEqual(got, want) {
		t.Fatalf("nginx calls=%v want=%v", got, want)
	}
}

func TestApplyAllNginxTestFailureRestoresEveryManagedFile(t *testing.T) {
	env := setupApplyAllTest(t, true)
	if err := ApplyAll(); err != nil {
		t.Fatal(err)
	}
	clearNginxCalls(t, env.callLog)

	oldCAPath := UpstreamCAPath(42)
	if err := os.MkdirAll(filepath.Dir(oldCAPath), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(oldCAPath, []byte("old-ca\n"), 0644); err != nil {
		t.Fatal(err)
	}
	oldOtherProtocol := filepath.Join(config.Global.Nginx.ConfDir, "42-stream.conf")
	if err := os.WriteFile(oldOtherProtocol, []byte("old-stream\n"), 0644); err != nil {
		t.Fatal(err)
	}
	for _, path := range nginxPackageDefaultPaths {
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(nginxPackageDefaultPaths[0], []byte("package-default\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../available/default", nginxPackageDefaultPaths[1]); err != nil {
		t.Fatal(err)
	}

	if _, err := db.DB.Exec(`INSERT INTO ssl_certs(id,domain,cert_pem,key_pem,expire_at,auto_renew)
		VALUES(1,'api.example.invalid','test-cert','test-key','2099-01-01',0)`); err != nil {
		t.Fatal(err)
	}
	ca := testCAPEM(t)
	if _, err := db.DB.Exec(`UPDATE rules SET listen_port=0,https_enabled=1,https_port=10443,
		ssl_cert_id=1,upstream_protocol='https',proxy_ssl_name='origin.example.invalid',
		proxy_ssl_verify=1,proxy_ssl_trusted_ca_pem=?,proxy_ssl_verify_depth=5,
		proxy_read_timeout=660,log_max_size='9M' WHERE id=42`, ca); err != nil {
		t.Fatal(err)
	}
	before := snapshotManagedTestFiles(t, env.root)
	t.Setenv("NGINX_TEST_EXIT", "1")
	if err := ApplyAll(); err == nil {
		t.Fatal("ApplyAll unexpectedly accepted failing nginx -t")
	}
	after := snapshotManagedTestFiles(t, env.root)
	if !reflect.DeepEqual(after, before) {
		t.Fatalf("managed file set was not fully restored\nbefore=%v\nafter=%v", before, after)
	}
	if got, want := readNginxCalls(t, env.callLog), []string{"TEST"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("nginx calls=%v want=%v", got, want)
	}
}

func TestApplyAllStartsOnceWhenNginxIsNotRunning(t *testing.T) {
	env := setupApplyAllTest(t, false)
	if err := ApplyAll(); err != nil {
		t.Fatal(err)
	}
	want := []string{"TEST", "START"}
	if got := readNginxCalls(t, env.callLog); !reflect.DeepEqual(got, want) {
		t.Fatalf("nginx calls=%v want=%v", got, want)
	}
}

func TestApplyAllUnchangedStartsOnceWhenNginxStops(t *testing.T) {
	env := setupApplyAllTest(t, true)
	if err := ApplyAll(); err != nil {
		t.Fatal(err)
	}
	clearNginxCalls(t, env.callLog)
	if err := os.Remove(nginxPIDPath); err != nil {
		t.Fatal(err)
	}
	if err := ApplyAll(); err != nil {
		t.Fatal(err)
	}
	if got, want := readNginxCalls(t, env.callLog), []string{"START"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("nginx calls=%v want=%v", got, want)
	}
}

func TestApplyAllReloadFailureRestoresChangedFilesWithoutSecondReload(t *testing.T) {
	env := setupApplyAllTest(t, true)
	if err := ApplyAll(); err != nil {
		t.Fatal(err)
	}
	clearNginxCalls(t, env.callLog)
	before := snapshotManagedTestFiles(t, env.root)
	if _, err := db.DB.Exec(`UPDATE rules SET name='reload-fails' WHERE id=42`); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NGINX_RELOAD_EXIT", "1")
	if err := ApplyAll(); err == nil {
		t.Fatal("ApplyAll unexpectedly accepted failing reload")
	}
	after := snapshotManagedTestFiles(t, env.root)
	if !reflect.DeepEqual(after, before) {
		t.Fatalf("reload failure did not restore prior files\nbefore=%v\nafter=%v", before, after)
	}
	if got, want := readNginxCalls(t, env.callLog), []string{"TEST", "RELOAD"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("nginx calls=%v want=%v", got, want)
	}
}

type testFileState struct {
	Mode   os.FileMode
	Link   string
	Bytes  string
	Exists bool
}

func snapshotManagedTestFiles(t *testing.T, root string) map[string]testFileState {
	t.Helper()
	result := map[string]testFileState{}
	for _, top := range []string{
		config.Global.Nginx.ConfDir,
		config.Global.Nginx.CertDir,
		config.Global.Nginx.LogrotateDir,
		filepath.Join(root, "package"),
	} {
		_ = filepath.Walk(top, func(path string, info os.FileInfo, err error) error {
			if os.IsNotExist(err) {
				return nil
			}
			if err != nil {
				t.Fatal(err)
			}
			if info.IsDir() {
				return nil
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				t.Fatal(err)
			}
			state := testFileState{Mode: info.Mode(), Exists: true}
			if info.Mode()&os.ModeSymlink != 0 {
				state.Link, err = os.Readlink(path)
			} else {
				var data []byte
				data, err = os.ReadFile(path)
				state.Bytes = string(data)
			}
			if err != nil {
				t.Fatal(err)
			}
			result[rel] = state
			return nil
		})
	}
	// Stable map diagnostics make failures readable.
	keys := make([]string, 0, len(result))
	for key := range result {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return result
}
