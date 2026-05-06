package handler

import (
	"net"
	"strconv"

	"github.com/gin-gonic/gin"

	"ankerye-flow/db"
	"ankerye-flow/engine"
	"ankerye-flow/util"
)

// ── 黑名单 ──────────────────────────────────────────────────

func ListBlacklist(c *gin.Context) {
	rows, err := db.DB.Query(`SELECT id,type,value,note,hits,auto_added,enabled,created_at FROM filter_blacklist ORDER BY id DESC`)
	if err != nil {
		util.Fail(c, 500, err.Error()); return
	}
	defer rows.Close()
	list := []gin.H{}
	for rows.Next() {
		var id, hits, autoAdded, enabled int64
		var typ, value, note, createdAt string
		rows.Scan(&id, &typ, &value, &note, &hits, &autoAdded, &enabled, &createdAt)
		location := ""
		if typ == "ip" {
			location = util.LookupIP(value)
		} else if typ == "cidr" {
			if ip, _, err := net.ParseCIDR(value); err == nil {
				location = util.LookupIP(ip.String())
			}
		}
		list = append(list, gin.H{
			"id": id, "type": typ, "value": value, "note": note,
			"hits": hits, "auto_added": autoAdded, "enabled": enabled, "created_at": createdAt,
			"location": location,
		})
	}
	util.OK(c, list)
}

func AddBlacklist(c *gin.Context) {
	var body struct {
		Type  string `json:"type"  binding:"required"`
		Value string `json:"value" binding:"required"`
		Note  string `json:"note"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		util.Fail(c, 400, err.Error()); return
	}
	switch body.Type {
	case "ip":
		if net.ParseIP(body.Value) == nil {
			util.Fail(c, 400, "无效 IP 地址"); return
		}
	case "cidr":
		if _, _, err := net.ParseCIDR(body.Value); err != nil {
			util.Fail(c, 400, "无效 CIDR"); return
		}
	case "path", "ua", "method":
		if body.Value == "" {
			util.Fail(c, 400, "值不能为空"); return
		}
	default:
		util.Fail(c, 400, "类型必须是 ip/cidr/path/ua/method"); return
	}
	res, err := db.DB.Exec(
		`INSERT INTO filter_blacklist(type,value,note) VALUES(?,?,?)`,
		body.Type, body.Value, body.Note,
	)
	if err != nil {
		util.Fail(c, 409, "已存在相同条目"); return
	}
	id, _ := res.LastInsertId()
	engine.ApplyFilter()
	util.OK(c, gin.H{"id": id})
}

func DeleteBlacklist(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	var typ, value string
	db.DB.QueryRow(`SELECT type,value FROM filter_blacklist WHERE id=?`, id).Scan(&typ, &value)
	db.DB.Exec(`DELETE FROM filter_blacklist WHERE id=?`, id)
	if typ != "" {
		db.DB.Exec(`INSERT INTO sync_tombstones(table_name,record_key) VALUES('filter_blacklist',?)`, typ+":"+value)
	}
	engine.ApplyFilter()
	util.OK(c, gin.H{"id": id})
}

func EnableBlacklist(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	db.DB.Exec(`UPDATE filter_blacklist SET enabled=1,updated_at=datetime('now','localtime') WHERE id=?`, id)
	engine.ApplyFilter()
	util.OK(c, gin.H{"id": id})
}

func DisableBlacklist(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	db.DB.Exec(`UPDATE filter_blacklist SET enabled=0,updated_at=datetime('now','localtime') WHERE id=?`, id)
	engine.ApplyFilter()
	util.OK(c, gin.H{"id": id})
}

// ── 白名单 ──────────────────────────────────────────────────

func ListWhitelist(c *gin.Context) {
	rows, err := db.DB.Query(`SELECT id,type,value,note,enabled,created_at FROM filter_whitelist ORDER BY id DESC`)
	if err != nil {
		util.Fail(c, 500, err.Error()); return
	}
	defer rows.Close()
	list := []gin.H{}
	for rows.Next() {
		var id, enabled int64
		var typ, value, note, createdAt string
		rows.Scan(&id, &typ, &value, &note, &enabled, &createdAt)
		list = append(list, gin.H{
			"id": id, "type": typ, "value": value, "note": note,
			"enabled": enabled, "created_at": createdAt,
		})
	}
	util.OK(c, list)
}

func AddWhitelist(c *gin.Context) {
	var body struct {
		Type  string `json:"type"  binding:"required"`
		Value string `json:"value" binding:"required"`
		Note  string `json:"note"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		util.Fail(c, 400, err.Error()); return
	}
	switch body.Type {
	case "ip":
		if net.ParseIP(body.Value) == nil {
			util.Fail(c, 400, "无效 IP 地址"); return
		}
	case "cidr":
		if _, _, err := net.ParseCIDR(body.Value); err != nil {
			util.Fail(c, 400, "无效 CIDR"); return
		}
	default:
		util.Fail(c, 400, "白名单类型必须是 ip/cidr"); return
	}
	res, err := db.DB.Exec(
		`INSERT INTO filter_whitelist(type,value,note) VALUES(?,?,?)`,
		body.Type, body.Value, body.Note,
	)
	if err != nil {
		util.Fail(c, 409, "已存在相同条目"); return
	}
	id, _ := res.LastInsertId()
	engine.ApplyFilter()
	util.OK(c, gin.H{"id": id})
}

func DeleteWhitelist(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	var typ, value string
	db.DB.QueryRow(`SELECT type,value FROM filter_whitelist WHERE id=?`, id).Scan(&typ, &value)
	db.DB.Exec(`DELETE FROM filter_whitelist WHERE id=?`, id)
	if typ != "" {
		db.DB.Exec(`INSERT INTO sync_tombstones(table_name,record_key) VALUES('filter_whitelist',?)`, typ+":"+value)
	}
	engine.ApplyFilter()
	util.OK(c, gin.H{"id": id})
}

func EnableWhitelist(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	db.DB.Exec(`UPDATE filter_whitelist SET enabled=1,updated_at=datetime('now','localtime') WHERE id=?`, id)
	engine.ApplyFilter()
	util.OK(c, gin.H{"id": id})
}

func DisableWhitelist(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	db.DB.Exec(`UPDATE filter_whitelist SET enabled=0,updated_at=datetime('now','localtime') WHERE id=?`, id)
	engine.ApplyFilter()
	util.OK(c, gin.H{"id": id})
}

func ApplyFilterNow(c *gin.Context) {
	if err := engine.ApplyFilter(); err != nil {
		util.Fail(c, 500, err.Error()); return
	}
	util.OK(c, gin.H{"msg": "过滤规则已应用"})
}
