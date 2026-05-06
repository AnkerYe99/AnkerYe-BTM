package handler

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/gin-gonic/gin"

	"ankerye-flow/config"
	"ankerye-flow/db"
	"ankerye-flow/util"
)

// captureEntry 一条捕获到的请求（来自 rule_X_capture.log JSON 行）
type captureEntry struct {
	Time        string `json:"time"`
	IP          string `json:"ip"`
	Location    string `json:"location,omitempty"`
	Method      string `json:"method"`
	URI         string `json:"uri"`
	Status      int    `json:"status"`
	ReqTime     any    `json:"req_time"`
	UpTime      string `json:"up_time"`
	Upstream    string `json:"upstream"`
	ContentType string `json:"content_type"`
	UA          string `json:"ua"`
	Body        string `json:"body"`
}

// ListCapture 返回某规则最近 N 条捕获请求（默认 200）。
// query: limit=200, method=POST, status=200, kw=keyword
func ListCapture(c *gin.Context) {
	ruleID, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	if ruleID <= 0 {
		util.Fail(c, 400, "rule id 非法")
		return
	}

	// 校验规则存在 + 已开启 capture
	var captureBody int
	var ruleName string
	err := db.DB.QueryRow(`SELECT IFNULL(capture_body,0), name FROM rules WHERE id=?`, ruleID).Scan(&captureBody, &ruleName)
	if err != nil {
		util.Fail(c, 404, "规则不存在")
		return
	}

	logFile := filepath.Join(config.Global.Nginx.LogDir, fmt.Sprintf("rule_%d_capture.log", ruleID))

	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "200"))
	if limit <= 0 || limit > 5000 {
		limit = 200
	}
	methodFilter := c.Query("method")
	statusFilter := c.Query("status")
	kw := c.Query("kw")

	f, err := os.Open(logFile)
	if err != nil {
		util.OK(c, gin.H{
			"capture_enabled": captureBody == 1,
			"rule_name":       ruleName,
			"total":           0,
			"list":            []captureEntry{},
			"hint":            "capture log 还没产生数据（需先启用 capture 并接到请求）",
		})
		return
	}
	defer f.Close()

	// 简单粗暴：读全文按行分割（capture log 已自动轮转，单文件不会过大），
	// 只取最后 limit 条匹配的。
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024) // 1MB 单行上限

	var all []captureEntry
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		var e captureEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			continue
		}
		if methodFilter != "" && e.Method != methodFilter {
			continue
		}
		if statusFilter != "" {
			if s, err := strconv.Atoi(statusFilter); err == nil && e.Status != s {
				continue
			}
		}
		if kw != "" && !contains(e.URI, kw) && !contains(e.Body, kw) {
			continue
		}
		// 补归属地
		if e.IP != "" {
			e.Location = util.LookupIP(e.IP)
		}
		all = append(all, e)
	}

	// 倒序（最近的在前），并裁剪到 limit
	for i, j := 0, len(all)-1; i < j; i, j = i+1, j-1 {
		all[i], all[j] = all[j], all[i]
	}
	if len(all) > limit {
		all = all[:limit]
	}

	util.OK(c, gin.H{
		"capture_enabled": captureBody == 1,
		"rule_name":       ruleName,
		"total":           len(all),
		"list":            all,
	})
}

func contains(s, sub string) bool {
	if len(sub) == 0 {
		return true
	}
	if len(s) < len(sub) {
		return false
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
