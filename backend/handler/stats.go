package handler

import (
	"runtime"
	"syscall"

	"github.com/gin-gonic/gin"

	"nginxflow/db"
	"nginxflow/util"
)

func Overview(c *gin.Context) {
	var ruleCount, serverCount, upCount, certCount, certExpiring int
	db.DB.QueryRow(`SELECT COUNT(*) FROM rules`).Scan(&ruleCount)
	db.DB.QueryRow(`SELECT COUNT(*) FROM upstream_servers`).Scan(&serverCount)
	db.DB.QueryRow(`SELECT COUNT(*) FROM upstream_servers WHERE state='up'`).Scan(&upCount)
	db.DB.QueryRow(`SELECT COUNT(*) FROM ssl_certs`).Scan(&certCount)
	db.DB.QueryRow(`SELECT COUNT(*) FROM ssl_certs WHERE expire_at <= datetime('now','localtime','+10 days')`).Scan(&certExpiring)

	healthRate := 0.0
	if serverCount > 0 {
		healthRate = float64(upCount) / float64(serverCount) * 100
	}
	util.OK(c, gin.H{
		"rule_count":     ruleCount,
		"server_count":   serverCount,
		"up_count":       upCount,
		"health_rate":    healthRate,
		"cert_count":     certCount,
		"cert_expiring":  certExpiring,
	})
}

func Health(c *gin.Context) {
	rows, _ := db.DB.Query(`SELECT s.id,s.rule_id,r.name,s.address,s.port,s.weight,s.state,
		IFNULL(s.last_check_at,''),IFNULL(s.last_err,'')
		FROM upstream_servers s LEFT JOIN rules r ON s.rule_id=r.id
		ORDER BY s.rule_id, s.id`)
	defer rows.Close()
	list := []gin.H{}
	for rows.Next() {
		var id, ruleID int64
		var name, addr, state, lastCheck, lastErr string
		var port, weight int
		rows.Scan(&id, &ruleID, &name, &addr, &port, &weight, &state, &lastCheck, &lastErr)
		list = append(list, gin.H{
			"id": id, "rule_id": ruleID, "rule_name": name,
			"address": addr, "port": port, "weight": weight, "state": state,
			"last_check_at": lastCheck, "last_err": lastErr,
		})
	}
	util.OK(c, list)
}

func System(c *gin.Context) {
	var si syscall.Sysinfo_t
	syscall.Sysinfo(&si)
	memTotal := uint64(si.Totalram) * uint64(si.Unit)
	memFree := uint64(si.Freeram) * uint64(si.Unit)

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	util.OK(c, gin.H{
		"mem_total":       memTotal,
		"mem_free":        memFree,
		"mem_used":        memTotal - memFree,
		"uptime_sec":      si.Uptime,
		"load1":           float64(si.Loads[0]) / 65536.0,
		"load5":           float64(si.Loads[1]) / 65536.0,
		"load15":          float64(si.Loads[2]) / 65536.0,
		"go_goroutines":   runtime.NumGoroutine(),
		"go_heap_alloc":   m.HeapAlloc,
	})
}
