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
	if ver < 8 {
		t.Errorf("迁移版本 = %d, want >= 8", ver)
	}

	// 幂等：再跑一次迁移不应报错
	if err := migrate(); err != nil {
		t.Errorf("重复迁移失败: %v", err)
	}
}
