package handler

import (
	"database/sql"
	"fmt"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"ankerye-flow/db"
	"ankerye-flow/engine"
	"ankerye-flow/health"
	"ankerye-flow/util"
)

type ruleReq struct {
	Name         string       `json:"name" binding:"required"`
	Protocol     string       `json:"protocol" binding:"required"` // http / tcp / udp
	ListenPort   int          `json:"listen_port"` // HTTP port for http; proxy port for tcp/udp; 0 = HTTPS-only
	ListenStack  string       `json:"listen_stack"`
	HTTPSEnabled int          `json:"https_enabled"`
	HTTPSPort    *int         `json:"https_port"`
	ServerName   string       `json:"server_name"`
	LBMethod     string       `json:"lb_method"`
	SSLCertID    *int64       `json:"ssl_cert_id"`
	SSLRedirect  int          `json:"ssl_redirect"`
	HCEnabled    int          `json:"hc_enabled"`
	HCInterval   int          `json:"hc_interval"`
	HCTimeout    int          `json:"hc_timeout"`
	HCPath       string       `json:"hc_path"`
	HCRise       int          `json:"hc_rise"`
	HCFall       int          `json:"hc_fall"`
	LogMaxSize   string       `json:"log_max_size"`
	CustomConfig string       `json:"custom_config"`
	Servers      []serverItem `json:"servers"`
}

type serverItem struct {
	Address string `json:"address"`
	Port    int    `json:"port"`
	Weight  int    `json:"weight"`
	State   string `json:"state"`
}

func ListRules(c *gin.Context) {
	protocolFilter := c.Query("protocol")
	statusFilter := c.Query("status")
	q := `SELECT id,name,protocol,listen_port,IFNULL(listen_stack,'both'),
		https_enabled,https_port,server_name,lb_method,
		ssl_cert_id,hc_enabled,log_max_size,status,created_at,updated_at FROM rules WHERE 1=1`
	args := []interface{}{}
	if protocolFilter != "" {
		q += ` AND protocol=?`
		args = append(args, protocolFilter)
	}
	if statusFilter != "" {
		q += ` AND status=?`
		args = append(args, statusFilter)
	}
	q += ` ORDER BY id DESC`
	rows, err := db.DB.Query(q, args...)
	if err != nil {
		util.Fail(c, 500, err.Error())
		return
	}
	type rowT struct {
		id                               int64
		name, proto, stack, srvName, lbm string
		logSize, createdAt, updated      string
		port, hcEnabled, status          int
		httpsEnabled                     int
		httpsPort                        sql.NullInt64
		sslCertID                        sql.NullInt64
	}
	items := []rowT{}
	for rows.Next() {
		var r rowT
		rows.Scan(&r.id, &r.name, &r.proto, &r.port, &r.stack,
			&r.httpsEnabled, &r.httpsPort, &r.srvName, &r.lbm,
			&r.sslCertID, &r.hcEnabled, &r.logSize, &r.status, &r.createdAt, &r.updated)
		items = append(items, r)
	}
	rows.Close()
	list := []gin.H{}
	for _, r := range items {
		var srvCount, upCount sql.NullInt64
		db.DB.QueryRow(`SELECT COUNT(*), SUM(CASE WHEN state='up' THEN 1 ELSE 0 END) FROM upstream_servers WHERE rule_id=?`, r.id).Scan(&srvCount, &upCount)
		var addrs string
		db.DB.QueryRow(`SELECT GROUP_CONCAT(address || ':' || port, ', ') FROM upstream_servers WHERE rule_id=?`, r.id).Scan(&addrs)
		h := gin.H{
			"id": r.id, "name": r.name, "protocol": r.proto, "listen_port": r.port,
			"listen_stack":  r.stack,
			"https_enabled": r.httpsEnabled,
			"https_port":    nullableInt64(r.httpsPort),
			"server_name":   r.srvName, "lb_method": r.lbm,
			"ssl_cert_id":  nullableInt64(r.sslCertID),
			"hc_enabled":   r.hcEnabled, "log_max_size": r.logSize, "status": r.status,
			"server_count": srvCount.Int64, "up_count": upCount.Int64,
			"created_at": r.createdAt, "updated_at": r.updated,
			"addresses": addrs,
		}
		list = append(list, h)
	}
	util.OK(c, list)
}

func GetRule(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	r, err := engine.LoadRule(id)
	if err != nil {
		util.Fail(c, 404, "规则不存在")
		return
	}
	util.OK(c, r)
}

func CreateRule(c *gin.Context) {
	var req ruleReq
	if err := c.ShouldBindJSON(&req); err != nil {
		util.Fail(c, 400, "参数错误: "+err.Error())
		return
	}
	if err := validateRule(&req); err != nil {
		util.Fail(c, 400, err.Error())
		return
	}
	if err := checkConflict(&req, 0); err != nil {
		util.Fail(c, 400, err.Error())
		return
	}

	fillDefaults(&req)

	tx, _ := db.DB.Begin()
	var sslCertID interface{}
	if req.SSLCertID != nil {
		sslCertID = *req.SSLCertID
	}
	var httpsPort interface{}
	if req.HTTPSPort != nil {
		httpsPort = *req.HTTPSPort
	}
	res, err := tx.Exec(`INSERT INTO rules(name,protocol,listen_port,listen_stack,
		https_enabled,https_port,server_name,lb_method,
		ssl_cert_id,ssl_redirect,hc_enabled,hc_interval,hc_timeout,hc_path,hc_rise,hc_fall,
		log_max_size,custom_config) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		req.Name, req.Protocol, req.ListenPort, req.ListenStack,
		req.HTTPSEnabled, httpsPort, req.ServerName, req.LBMethod,
		sslCertID, req.SSLRedirect, req.HCEnabled, req.HCInterval, req.HCTimeout,
		req.HCPath, req.HCRise, req.HCFall, req.LogMaxSize, req.CustomConfig)
	if err != nil {
		tx.Rollback()
		util.Fail(c, 500, err.Error())
		return
	}
	ruleID, _ := res.LastInsertId()
	for _, s := range req.Servers {
		state := s.State
		if state == "" {
			state = "up"
		}
		w := s.Weight
		if w <= 0 {
			w = 1
		}
		tx.Exec(`INSERT INTO upstream_servers(rule_id,address,port,weight,state) VALUES(?,?,?,?,?)`,
			ruleID, s.Address, s.Port, w, state)
	}
	tx.Commit()

	if err := engine.ApplyRule(ruleID); err != nil {
		db.DB.Exec(`DELETE FROM rules WHERE id=?`, ruleID)
		util.Fail(c, 500, "nginx配置生成失败: "+err.Error())
		return
	}
	health.RestartRule(ruleID)
	util.OK(c, gin.H{"id": ruleID})
}

func UpdateRule(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	var req ruleReq
	if err := c.ShouldBindJSON(&req); err != nil {
		util.Fail(c, 400, "参数错误")
		return
	}
	if err := validateRule(&req); err != nil {
		util.Fail(c, 400, err.Error())
		return
	}
	if err := checkConflict(&req, id); err != nil {
		util.Fail(c, 400, err.Error())
		return
	}

	fillDefaults(&req)

	tx, _ := db.DB.Begin()
	var sslCertID interface{}
	if req.SSLCertID != nil {
		sslCertID = *req.SSLCertID
	}
	var httpsPort interface{}
	if req.HTTPSPort != nil {
		httpsPort = *req.HTTPSPort
	}
	_, err := tx.Exec(`UPDATE rules SET name=?,protocol=?,listen_port=?,listen_stack=?,
		https_enabled=?,https_port=?,server_name=?,lb_method=?,
		ssl_cert_id=?,ssl_redirect=?,hc_enabled=?,hc_interval=?,hc_timeout=?,hc_path=?,
		hc_rise=?,hc_fall=?,log_max_size=?,custom_config=?,updated_at=datetime('now','localtime')
		WHERE id=?`,
		req.Name, req.Protocol, req.ListenPort, req.ListenStack,
		req.HTTPSEnabled, httpsPort, req.ServerName, req.LBMethod, sslCertID,
		req.SSLRedirect, req.HCEnabled, req.HCInterval, req.HCTimeout, req.HCPath,
		req.HCRise, req.HCFall, req.LogMaxSize, req.CustomConfig, id)
	if err != nil {
		tx.Rollback()
		util.Fail(c, 500, err.Error())
		return
	}
	tx.Exec(`DELETE FROM upstream_servers WHERE rule_id=?`, id)
	for _, s := range req.Servers {
		state := s.State
		if state == "" {
			state = "up"
		}
		w := s.Weight
		if w <= 0 {
			w = 1
		}
		tx.Exec(`INSERT INTO upstream_servers(rule_id,address,port,weight,state) VALUES(?,?,?,?,?)`,
			id, s.Address, s.Port, w, state)
	}
	tx.Commit()

	if err := engine.ApplyRule(id); err != nil {
		util.Fail(c, 500, "nginx配置生成失败: "+err.Error())
		return
	}
	health.RestartRule(id)
	util.OK(c, gin.H{"id": id})
}

func DeleteRule(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	health.StopRule(id)
	engine.DeleteRule(id)
	db.DB.Exec(`DELETE FROM rules WHERE id=?`, id)
	util.OK(c, gin.H{"deleted": id})
}

func EnableRule(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	db.DB.Exec(`UPDATE rules SET status=1 WHERE id=?`, id)
	if err := engine.ApplyRule(id); err != nil {
		util.Fail(c, 500, err.Error())
		return
	}
	health.RestartRule(id)
	util.OK(c, nil)
}

func DisableRule(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	db.DB.Exec(`UPDATE rules SET status=0 WHERE id=?`, id)
	health.StopRule(id)
	r, _ := engine.LoadRule(id)
	if r != nil {
		engine.DeleteRule(id)
	}
	engine.Reload()
	util.OK(c, nil)
}

func PreviewRule(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	text, err := engine.PreviewRule(id)
	if err != nil {
		util.Fail(c, 404, err.Error())
		return
	}
	util.OK(c, gin.H{"config": text})
}

// validateRule checks rule fields for validity.
func validateRule(r *ruleReq) error {
	valid := map[string]bool{"http": true, "tcp": true, "udp": true, "tcpudp": true}
	if !valid[r.Protocol] {
		return errMsg("protocol 必须是 http/tcp/udp/tcpudp")
	}
	validStack := map[string]bool{"": true, "v4": true, "v6": true, "both": true}
	if !validStack[r.ListenStack] {
		return errMsg("listen_stack 必须是 v4/v6/both")
	}
	if r.Protocol == "http" {
		httpsOnly := r.HTTPSEnabled == 1 && r.ListenPort == 0
		if !httpsOnly && (r.ListenPort <= 0 || r.ListenPort > 65535) {
			return errMsg("HTTP 端口号无效")
		}
		if r.HTTPSEnabled == 1 {
			if r.HTTPSPort == nil || *r.HTTPSPort <= 0 || *r.HTTPSPort > 65535 {
				return errMsg("HTTPS 端口号无效")
			}
			if r.ListenPort > 0 && r.ListenPort == *r.HTTPSPort {
				return errMsg("HTTP 端口与 HTTPS 端口不能相同")
			}
			if r.SSLCertID == nil {
				return errMsg("启用 HTTPS 时必须选择 SSL 证书")
			}
		}
	} else {
		if r.ListenPort <= 0 || r.ListenPort > 65535 {
			return errMsg("端口号无效")
		}
	}
	if len(r.Servers) == 0 {
		return errMsg("至少需要一个后端节点")
	}
	return nil
}

// parseDomains splits space-separated server_name into lowercase domain list (excluding wildcards).
func parseDomains(serverName string) []string {
	var out []string
	for _, d := range strings.Fields(serverName) {
		d = strings.ToLower(d)
		if d != "_" && d != "" {
			out = append(out, d)
		}
	}
	return out
}

// checkConflict checks port and domain-port uniqueness.
func checkConflict(req *ruleReq, excludeID int64) error {
	stack := req.ListenStack
	if stack == "" {
		stack = "both"
	}

	if req.Protocol == "http" {
		// For HTTP rules: check domain+port uniqueness.
		// A wildcard-only rule also does a port-level check to avoid nginx default server collision.
		domains := parseDomains(req.ServerName)

		// Collect all other HTTP rules
		rows, err := db.DB.Query(`SELECT id, server_name, listen_port, https_enabled, https_port
			FROM rules WHERE protocol='http' AND id!=?`, excludeID)
		if err != nil {
			return err
		}
		var others []struct {
			id           int64
			sn           string
			port         int
			httpsEnabled int
			httpsPort    sql.NullInt64
		}
		for rows.Next() {
			var o struct {
				id           int64
				sn           string
				port         int
				httpsEnabled int
				httpsPort    sql.NullInt64
			}
			rows.Scan(&o.id, &o.sn, &o.port, &o.httpsEnabled, &o.httpsPort)
			others = append(others, o)
		}
		rows.Close()

		// Build set of ports used by this new rule
		myPorts := []int{req.ListenPort}
		if req.HTTPSEnabled == 1 && req.HTTPSPort != nil {
			myPorts = append(myPorts, *req.HTTPSPort)
		}

		for _, o := range others {
			otherDomains := parseDomains(o.sn)
			otherPorts := []int{o.port}
			if o.httpsEnabled == 1 && o.httpsPort.Valid {
				otherPorts = append(otherPorts, int(o.httpsPort.Int64))
			}

			if len(domains) == 0 || len(otherDomains) == 0 {
				// One of them is wildcard "_": check port collision
				for _, mp := range myPorts {
					for _, op := range otherPorts {
						if mp == op {
							return fmt.Errorf("端口 %d 已被规则 id=%d 占用（默认虚拟主机冲突）", mp, o.id)
						}
					}
				}
			} else {
				// Named domains: check (domain, port) uniqueness
				for _, d := range domains {
					for _, od := range otherDomains {
						if d == od {
							for _, mp := range myPorts {
								for _, op := range otherPorts {
									if mp == op {
										return fmt.Errorf("域名 %s 在端口 %d 已被规则 id=%d 使用", d, mp, o.id)
									}
								}
							}
						}
					}
				}
			}
		}
	} else {
		// TCP/UDP: port must be globally unique per stack
		rows, err := db.DB.Query(`SELECT id, IFNULL(listen_stack,'both') FROM rules
			WHERE protocol=? AND id!=?`, req.Protocol, excludeID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id int64
			var otherStack string
			rows.Scan(&id, &otherStack)
			if stack == "both" || otherStack == "both" || stack == otherStack {
				return fmt.Errorf("端口 %d (%s) 已被规则 id=%d 占用", req.ListenPort, stack, id)
			}
		}
	}
	return nil
}

func fillDefaults(r *ruleReq) {
	if r.LBMethod == "" {
		r.LBMethod = "round_robin"
	}
	if r.ListenStack == "" {
		r.ListenStack = "both"
	}
	if r.HCInterval == 0 {
		r.HCInterval = 10
	}
	if r.HCTimeout == 0 {
		r.HCTimeout = 3
	}
	if r.HCPath == "" {
		r.HCPath = "/"
	}
	if r.HCRise == 0 {
		r.HCRise = 2
	}
	if r.HCFall == 0 {
		r.HCFall = 3
	}
	if r.LogMaxSize == "" {
		r.LogMaxSize = "5M"
	}
}

type errMsgT string

func (e errMsgT) Error() string { return string(e) }
func errMsg(s string) error     { return errMsgT(s) }

func nullableInt64(n sql.NullInt64) interface{} {
	if n.Valid {
		return n.Int64
	}
	return nil
}
