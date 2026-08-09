package handler

import (
	"os"
	"path/filepath"
	"testing"

	"ankerye-flow/db"
	"ankerye-flow/engine"
)

// 主从指纹必须逐字节相等，否则从节点要么永远认为"有变化"（每轮全量拉，白耗流量、
// 且掩盖真正的不同步），要么永远认为"没变化"（改了不同步）。
// 这里直接跑两条真实代码路径——主节点 queryRulesForExport+hashRules、
// 从节点 engine.LocalRulesMD5——比对结果，能抓住"两边 SELECT 字段/IFNULL 默认值不一致"。
func setupFPDB(t *testing.T) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fp.db")
	t.Cleanup(func() { os.Remove(path) })
	if err := db.Init(path); err != nil {
		t.Fatalf("db.Init: %v", err)
	}
	t.Cleanup(func() { db.DB.Close() })

	db.DB.Exec(`INSERT INTO ssl_certs(id,domain,cert_pem,key_pem,expire_at)
		VALUES(1,'a.example.com','CERT','KEY','2027-01-01')`)
	db.DB.Exec(`INSERT INTO rules(id,name,protocol,listen_port,listen_stack,https_enabled,https_port,
		server_name,lb_method,ssl_cert_id,ssl_redirect,hc_enabled,hc_interval,hc_timeout,
		hc_path,hc_host,hc_rise,hc_fall,log_max_size,capture_max_size,custom_config,capture_body,
		ip_acl_mode,ip_acl_list,status)
		VALUES(1,'r1','http',80,'both',1,443,'a.example.com','round_robin',1,0,1,10,3,
		'/','a.example.com',2,3,'5M','5M','',0,'allow','118.143.68.96/28',1)`)
	db.DB.Exec(`INSERT INTO rules(id,name,protocol,listen_port,lb_method,hc_path,hc_host)
		VALUES(2,'r2','tcp',9000,'round_robin','/','')`)
	db.DB.Exec(`INSERT INTO upstream_servers(rule_id,address,port,weight,state)
		VALUES(1,'10.0.0.1',8080,1,'up'),(1,'10.0.0.2',8080,2,'up'),(2,'10.0.0.3',9000,1,'up')`)
}

func TestMasterSlaveFingerprintMatch(t *testing.T) {
	setupFPDB(t)

	master := hashRules(queryRulesForExport())
	slave := engine.LocalRulesMD5()
	if master != slave {
		t.Fatalf("主从指纹不一致——从节点会永远误判有变化并全量拉取\n主: %s\n从: %s", master, slave)
	}
	if master == "" {
		t.Fatal("指纹为空")
	}
}

// 核心回归：改了规则的任一同步字段，指纹就必须变，否则从节点收不到这次改动。
func TestFingerprintChangesOnFieldUpdate(t *testing.T) {
	setupFPDB(t)
	base := hashRules(queryRulesForExport())

	cases := []struct {
		name string
		sql  string
	}{
		{"ip_acl_mode", `UPDATE rules SET ip_acl_mode='deny' WHERE id=1`},
		{"ip_acl_list", `UPDATE rules SET ip_acl_list='1.2.3.4' WHERE id=1`},
		{"hc_host", `UPDATE rules SET hc_host='changed.example.com' WHERE id=1`},
		{"capture_body", `UPDATE rules SET capture_body=1 WHERE id=1`},
		{"custom_config", `UPDATE rules SET custom_config='add_header X-T 1;' WHERE id=1`},
		{"server_name", `UPDATE rules SET server_name='b.example.com' WHERE id=1`},
		{"status", `UPDATE rules SET status=0 WHERE id=1`},
		{"upstream", `UPDATE upstream_servers SET weight=9 WHERE rule_id=1 AND address='10.0.0.1'`},
	}
	seen := map[string]string{base: "初始"}
	for _, c := range cases {
		if _, err := db.DB.Exec(c.sql); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		got := hashRules(queryRulesForExport())
		if prev, dup := seen[got]; dup {
			t.Errorf("改动 %s 后指纹未变（与「%s」相同）——这次改动不会同步到从节点", c.name, prev)
		}
		seen[got] = c.name

		// 每一步都要保持主从一致
		if slave := engine.LocalRulesMD5(); slave != got {
			t.Errorf("改动 %s 后主从指纹分叉\n主: %s\n从: %s", c.name, got, slave)
		}
	}
}
