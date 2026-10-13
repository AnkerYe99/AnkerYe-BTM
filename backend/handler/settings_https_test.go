package handler

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"

	"ankerye-flow/db"
)

func TestBackupIncludesHTTPSUpstreamFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "backup.db")
	if err := db.Init(path); err != nil {
		t.Fatal(err)
	}
	defer db.DB.Close()
	if _, err := db.DB.Exec(`INSERT INTO rules(name,protocol,listen_port,lb_method,server_name,
		upstream_protocol,proxy_ssl_name,proxy_ssl_verify,proxy_ssl_verify_depth,proxy_read_timeout)
		VALUES('r','http',80,'round_robin','api.example.invalid','https','origin.example.invalid',1,6,660)`); err != nil {
		t.Fatal(err)
	}
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/api/v1/settings/backup", nil)
	Backup(c)
	plain, err := decryptBackup(w.Body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	var data backupData
	if err := json.Unmarshal(plain, &data); err != nil {
		t.Fatal(err)
	}
	if len(data.Rules) != 1 {
		t.Fatalf("rules=%d", len(data.Rules))
	}
	r := data.Rules[0]
	if r["upstream_protocol"] != "https" || r["proxy_ssl_name"] != "origin.example.invalid" ||
		int64v(r["proxy_ssl_verify_depth"]) != 6 || int64v(r["proxy_read_timeout"]) != 660 {
		t.Fatalf("HTTPS upstream fields missing from backup: %#v", r)
	}
}

func TestRestoreOldFormatGetsSafeDefaults(t *testing.T) {
	m := map[string]interface{}{
		"protocol": "http", "server_name": "api.example.invalid",
	}
	proto, name, verify, ca, depth, timeout, err := restoreUpstreamValues(m)
	if err != nil {
		t.Fatal(err)
	}
	if proto != "http" || name != "" || verify != 1 || ca != "" || depth != 5 || timeout != 60 {
		t.Fatalf("old backup defaults wrong: %s %q %d %q %d %d", proto, name, verify, ca, depth, timeout)
	}
}
