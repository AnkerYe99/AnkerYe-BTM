package handler

import (
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/gin-gonic/gin"

	"ankerye-flow/db"
	"ankerye-flow/util"
)

// RuleTraffic 返回各规则流量统计，period=today/7d/30d/all
func RuleTraffic(c *gin.Context) {
	period := c.DefaultQuery("period", "today")
	var condition string
	switch period {
	case "today":
		condition = `AND date = date('now','localtime')`
	case "24h":
		condition = `AND date >= date('now','localtime','-1 day')`
	case "7d":
		condition = `AND date >= date('now','localtime','-6 days')`
	case "30d":
		condition = `AND date >= date('now','localtime','-29 days')`
	default:
		condition = ""
	}

	query := `SELECT r.id, r.name, r.protocol,
		IFNULL(SUM(s.requests),0), IFNULL(SUM(s.bytes_out),0),
		IFNULL(SUM(s.s1xx),0), IFNULL(SUM(s.s2xx),0),
		IFNULL(SUM(s.s3xx),0), IFNULL(SUM(s.s4xx),0), IFNULL(SUM(s.s5xx),0)
		FROM rules r
		LEFT JOIN rule_stats s ON s.rule_id=r.id ` + condition + `
		GROUP BY r.id ORDER BY r.id`

	rows, err := db.DB.Query(query)
	if err != nil {
		util.Fail(c, 500, err.Error())
		return
	}
	defer rows.Close()

	list := []gin.H{}
	for rows.Next() {
		var id int64
		var name, proto string
		var requests, bytesOut, s1xx, s2xx, s3xx, s4xx, s5xx int64
		rows.Scan(&id, &name, &proto, &requests, &bytesOut, &s1xx, &s2xx, &s3xx, &s4xx, &s5xx)
		list = append(list, gin.H{
			"id": id, "name": name, "protocol": proto,
			"requests":  requests,
			"bytes_out": bytesOut,
			"s1xx": s1xx, "s2xx": s2xx, "s3xx": s3xx,
			"s4xx": s4xx, "s5xx": s5xx,
		})
	}
	util.OK(c, list)
}

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

// ServerHealth 返回节点列表，含 today/7d/30d 三个维度的请求数和流量
func ServerHealth(c *gin.Context) {
	query := `
	SELECT r.id, r.name,
		s.id, s.address, s.port, s.weight, s.state,
		IFNULL(s.last_check_at,''), IFNULL(s.last_err,''),
		IFNULL(SUM(CASE WHEN st.date = date('now','localtime') THEN st.requests ELSE 0 END),0),
		IFNULL(SUM(CASE WHEN st.date = date('now','localtime') THEN st.bytes_out ELSE 0 END),0),
		IFNULL(SUM(CASE WHEN st.date >= date('now','localtime','-6 days') THEN st.requests ELSE 0 END),0),
		IFNULL(SUM(CASE WHEN st.date >= date('now','localtime','-6 days') THEN st.bytes_out ELSE 0 END),0),
		IFNULL(SUM(CASE WHEN st.date >= date('now','localtime','-29 days') THEN st.requests ELSE 0 END),0),
		IFNULL(SUM(CASE WHEN st.date >= date('now','localtime','-29 days') THEN st.bytes_out ELSE 0 END),0)
	FROM rules r
	JOIN upstream_servers s ON s.rule_id = r.id
	LEFT JOIN server_stats st ON st.server_id = s.id
	WHERE r.status = 1
	GROUP BY r.id, s.id
	ORDER BY r.id, s.id`

	rows, err := db.DB.Query(query)
	if err != nil {
		util.Fail(c, 500, err.Error())
		return
	}
	defer rows.Close()

	list := []gin.H{}
	for rows.Next() {
		var ruleID int64
		var ruleName string
		var sid int64
		var addr, state, lastCheck, lastErr string
		var port, weight int
		var todayReq, todayBytes, d7Req, d7Bytes, d30Req, d30Bytes int64
		rows.Scan(&ruleID, &ruleName,
			&sid, &addr, &port, &weight, &state, &lastCheck, &lastErr,
			&todayReq, &todayBytes, &d7Req, &d7Bytes, &d30Req, &d30Bytes)
		list = append(list, gin.H{
			"rule_id": ruleID, "rule_name": ruleName,
			"server_id": sid, "address": addr, "port": port, "weight": weight,
			"state": state, "last_check_at": lastCheck, "last_err": lastErr,
			"today_req": todayReq, "today_bytes": todayBytes,
			"d7_req": d7Req, "d7_bytes": d7Bytes,
			"d30_req": d30Req, "d30_bytes": d30Bytes,
		})
	}
	util.OK(c, list)
}

// readMemAvailable 从 /proc/meminfo 读取 MemAvailable（真正可用内存，Linux 内核计算，含可回收 cache）
func readMemAvailable() uint64 {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "MemAvailable:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				v, _ := strconv.ParseUint(fields[1], 10, 64)
				return v * 1024 // kB → bytes
			}
		}
	}
	return 0
}

func System(c *gin.Context) {
	var si syscall.Sysinfo_t
	syscall.Sysinfo(&si)
	memTotal := uint64(si.Totalram) * uint64(si.Unit)
	memAvail := readMemAvailable()
	memUsed := memTotal - memAvail

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	util.OK(c, gin.H{
		"mem_total":     memTotal,
		"mem_used":      memUsed,
		"mem_available": memAvail,
		"uptime_sec":    si.Uptime,
		"load1":         float64(si.Loads[0]) / 65536.0,
		"load5":         float64(si.Loads[1]) / 65536.0,
		"load15":        float64(si.Loads[2]) / 65536.0,
		"go_goroutines": runtime.NumGoroutine(),
		"go_heap_alloc": m.HeapAlloc,
	})
}
