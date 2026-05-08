package handler

import (
	"strconv"

	"github.com/gin-gonic/gin"

	"ankerye-flow/db"
	"ankerye-flow/engine"
	"ankerye-flow/health"
	"ankerye-flow/util"
)

func ListServers(c *gin.Context) {
	ruleID, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	rows, err := db.DB.Query(`SELECT id,rule_id,address,port,weight,state,fail_count,success_count,
		IFNULL(last_check_at,''),IFNULL(last_err,''),created_at FROM upstream_servers WHERE rule_id=? ORDER BY id`, ruleID)
	if err != nil {
		util.Fail(c, 500, err.Error())
		return
	}
	defer rows.Close()
	list := []gin.H{}
	for rows.Next() {
		var id, rid int64
		var addr, state, lastCheck, lastErr, createdAt string
		var port, weight, fc, sc int
		rows.Scan(&id, &rid, &addr, &port, &weight, &state, &fc, &sc, &lastCheck, &lastErr, &createdAt)
		list = append(list, gin.H{
			"id": id, "rule_id": rid, "address": addr, "port": port, "weight": weight,
			"state": state, "fail_count": fc, "success_count": sc,
			"last_check_at": lastCheck, "last_err": lastErr, "created_at": createdAt,
		})
	}
	util.OK(c, list)
}

func AddServer(c *gin.Context) {
	ruleID, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	var req struct {
		Address string `json:"address" binding:"required"`
		Port    int    `json:"port" binding:"required"`
		Weight  int    `json:"weight"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		util.Fail(c, 400, "参数错误")
		return
	}
	if req.Weight <= 0 {
		req.Weight = 1
	}
	res, err := db.DB.Exec(`INSERT INTO upstream_servers(rule_id,address,port,weight) VALUES(?,?,?,?)`,
		ruleID, req.Address, req.Port, req.Weight)
	if err != nil {
		util.Fail(c, 500, err.Error())
		return
	}
	sid, _ := res.LastInsertId()
	engine.ApplyRule(ruleID)
	health.RestartRule(ruleID)
	util.OK(c, gin.H{"id": sid})
}

func UpdateServer(c *gin.Context) {
	ruleID, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	sid, _ := strconv.ParseInt(c.Param("sid"), 10, 64)
	var req struct {
		Address string `json:"address"`
		Port    int    `json:"port"`
		Weight  int    `json:"weight"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		util.Fail(c, 400, "参数错误")
		return
	}
	if req.Weight <= 0 {
		req.Weight = 1
	}
	db.DB.Exec(`UPDATE upstream_servers SET address=?,port=?,weight=? WHERE id=? AND rule_id=?`,
		req.Address, req.Port, req.Weight, sid, ruleID)
	engine.ApplyRule(ruleID)
	util.OK(c, nil)
}

func DeleteServer(c *gin.Context) {
	ruleID, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	sid, _ := strconv.ParseInt(c.Param("sid"), 10, 64)
	db.DB.Exec(`DELETE FROM upstream_servers WHERE id=? AND rule_id=?`, sid, ruleID)
	engine.ApplyRule(ruleID)
	util.OK(c, nil)
}

func EnableServer(c *gin.Context) {
	ruleID, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	sid, _ := strconv.ParseInt(c.Param("sid"), 10, 64)
	db.DB.Exec(`UPDATE upstream_servers SET state='up',fail_count=0,success_count=0 WHERE id=? AND rule_id=?`, sid, ruleID)
	engine.ApplyRule(ruleID)
	util.OK(c, nil)
}

func DisableServer(c *gin.Context) {
	ruleID, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	sid, _ := strconv.ParseInt(c.Param("sid"), 10, 64)
	db.DB.Exec(`UPDATE upstream_servers SET state='disabled' WHERE id=? AND rule_id=?`, sid, ruleID)
	engine.ApplyRule(ruleID)
	util.OK(c, nil)
}

func ServerLogs(c *gin.Context) {
	sid, _ := strconv.ParseInt(c.Param("sid"), 10, 64)
	rows, err := db.DB.Query(`SELECT id,state,latency_ms,IFNULL(message,''),created_at FROM health_check_logs
		WHERE server_id=? ORDER BY id DESC LIMIT 100`, sid)
	if err != nil {
		util.Fail(c, 500, err.Error())
		return
	}
	defer rows.Close()
	list := []gin.H{}
	for rows.Next() {
		var id int64
		var state, msg, createdAt string
		var latency int
		rows.Scan(&id, &state, &latency, &msg, &createdAt)
		list = append(list, gin.H{"id": id, "state": state, "latency_ms": latency, "message": msg, "created_at": createdAt})
	}
	util.OK(c, list)
}
