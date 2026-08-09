package db

import (
	"os"
	"path/filepath"
	"testing"
)

// 验证：老库（无 ip_acl_* 字段）跑迁移后字段存在、默认值正确、旧数据不丢
func TestMigrateAddsIPACL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")
	defer os.Remove(path)

	if err := Init(path); err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer DB.Close()

	// 模拟迁移前就存在的老规则
	if _, err := DB.Exec(`INSERT INTO rules(name,protocol,listen_port,lb_method) VALUES('old','http',80,'round_robin')`); err != nil {
		t.Fatalf("insert: %v", err)
	}
	var mode, list string
	if err := DB.QueryRow(`SELECT IFNULL(ip_acl_mode,'?'),IFNULL(ip_acl_list,'?') FROM rules WHERE name='old'`).Scan(&mode, &list); err != nil {
		t.Fatalf("select: %v", err)
	}
	if mode != "off" || list != "" {
		t.Errorf("默认值不对: mode=%q list=%q, want off / 空", mode, list)
	}

	var ver int
	DB.QueryRow(`SELECT MAX(version) FROM _schema_version`).Scan(&ver)
	if ver < 9 {
		t.Errorf("迁移版本 = %d, want >= 9", ver)
	}

	// 幂等：再跑一次迁移不应报错
	if err := migrate(); err != nil {
		t.Errorf("重复迁移失败: %v", err)
	}
}

// 生产库里 v8 已被 add_blacklist_ttl 占用（2026-07-01 的 WAF 修复，源码未进本仓库）。
// 这里模拟那种库，确认本仓库的 ip_acl 迁移仍会被应用——
// 若哪天有人把它的版本号改回 8，这个测试会立刻失败。
func TestMigrateOnProdLikeDB(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "prod.db")
	defer os.Remove(path)

	if err := Init(path); err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer DB.Close()

	// 还原成"线上那种"库：去掉 ip_acl 字段与其版本记录，改成 v8=add_blacklist_ttl
	if _, err := DB.Exec(`ALTER TABLE rules DROP COLUMN ip_acl_mode`); err != nil {
		t.Skipf("当前 SQLite 不支持 DROP COLUMN，跳过: %v", err)
	}
	if _, err := DB.Exec(`ALTER TABLE rules DROP COLUMN ip_acl_list`); err != nil {
		t.Fatalf("drop ip_acl_list: %v", err)
	}
	DB.Exec(`DELETE FROM _schema_version WHERE version >= 8`)
	DB.Exec(`INSERT INTO _schema_version(version,name,applied_at) VALUES(8,'add_blacklist_ttl','2026-07-01 21:48:50')`)

	if err := migrate(); err != nil {
		t.Fatalf("在生产型库上迁移失败: %v", err)
	}

	var mode string
	if err := DB.QueryRow(`SELECT IFNULL(ip_acl_mode,'?') FROM rules LIMIT 1`).Scan(&mode); err != nil {
		// 没有数据行时用 PRAGMA 兜底确认列存在
		var found bool
		rows, _ := DB.Query(`PRAGMA table_info(rules)`)
		for rows.Next() {
			var cid int
			var name, typ string
			var notnull, pk int
			var dflt interface{}
			rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk)
			if name == "ip_acl_mode" {
				found = true
			}
		}
		rows.Close()
		if !found {
			t.Fatal("v8 被占用时 ip_acl 迁移被静默跳过——字段没加上")
		}
	}

	var ver int
	DB.QueryRow(`SELECT MAX(version) FROM _schema_version`).Scan(&ver)
	if ver != 9 {
		t.Errorf("迁移版本 = %d, want 9", ver)
	}
}
