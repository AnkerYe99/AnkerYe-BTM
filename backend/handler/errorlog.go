package handler

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"nginxflow/config"
	"nginxflow/db"
	"nginxflow/util"
)

var reAccessLog = regexp.MustCompile(
	`^(\S+) - \S+ \[(\d{2}/\w+/\d{4}):(\d{2}:\d{2}:\d{2}) [+-]\d{4}\] "([^"]*)" (\d{3}) (\d+) "[^"]*" "([^"]*)" (\S+)`)

var logMonthMap = map[string]string{
	"Jan": "01", "Feb": "02", "Mar": "03", "Apr": "04",
	"May": "05", "Jun": "06", "Jul": "07", "Aug": "08",
	"Sep": "09", "Oct": "10", "Nov": "11", "Dec": "12",
}

type errorLogEntry struct {
	Time     string `json:"time"`
	RuleID   int64  `json:"rule_id"`
	RuleName string `json:"rule_name"`
	IP       string `json:"ip"`
	Method   string `json:"method"`
	Path     string `json:"path"`
	Status   int    `json:"status"`
	Bytes    int64  `json:"bytes"`
	UA       string `json:"ua"`
	Upstream string `json:"upstream"`
}

func nginxTimeToISO(date, t string) string {
	parts := strings.Split(date, "/")
	if len(parts) != 3 {
		return date + " " + t
	}
	mon := logMonthMap[parts[1]]
	if mon == "" {
		mon = "00"
	}
	return parts[2] + "-" + mon + "-" + parts[0] + " " + t
}

// tailFileForDateRange 从文件末尾反向读取，遇到早于 startDate 的行立即停止。
// startDate / endDate 格式: "2026-04-19"（YYYY-MM-DD）。
// 返回结果已按正序排列，总量上限 maxEntries 防止内存爆炸。
func tailFileForDateRange(path, startDate, endDate string, maxEntries int) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil
	}
	fileSize := info.Size()
	if fileSize == 0 {
		return nil
	}

	buf := make([]byte, 128*1024)
	var collected []string
	pos := fileSize
	remainder := ""
	done := false

	for pos > 0 && !done && len(collected) < maxEntries {
		readSize := int64(len(buf))
		if pos < readSize {
			readSize = pos
		}
		pos -= readSize
		f.Seek(pos, 0)
		n, _ := f.Read(buf[:readSize])
		chunk := string(buf[:n]) + remainder
		lines := strings.Split(chunk, "\n")
		remainder = lines[0]

		for i := len(lines) - 1; i >= 1; i-- {
			line := lines[i]
			if line == "" {
				continue
			}
			m := reAccessLog.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			isoTime := nginxTimeToISO(m[2], m[3])
			lineDate := isoTime[:10]

			if lineDate < startDate {
				done = true
				break
			}
			if lineDate > endDate {
				continue
			}
			collected = append(collected, line)
			if len(collected) >= maxEntries {
				break
			}
		}
	}

	// 处理最头部那行（pos==0 时 remainder 还未入队）
	if !done && remainder != "" && len(collected) < maxEntries {
		m := reAccessLog.FindStringSubmatch(remainder)
		if m != nil {
			isoTime := nginxTimeToISO(m[2], m[3])
			lineDate := isoTime[:10]
			if lineDate >= startDate && lineDate <= endDate {
				collected = append(collected, remainder)
			}
		}
	}

	// 反转为正序（collected 目前是倒序）
	for i, j := 0, len(collected)-1; i < j; i, j = i+1, j-1 {
		collected[i], collected[j] = collected[j], collected[i]
	}
	return collected
}

func ListErrorLogs(c *gin.Context) {
	ruleIDStr := c.DefaultQuery("rule_id", "0")
	codeFilter := c.DefaultQuery("code", "all")

	// 日期范围，默认近 7 天
	now := time.Now()
	defaultEnd := now.Format("2006-01-02")
	defaultStart := now.AddDate(0, 0, -6).Format("2006-01-02")
	startDate := c.DefaultQuery("start", defaultStart)
	endDate := c.DefaultQuery("end", defaultEnd)

	// 基本校验：确保格式合法，否则回退默认值
	if len(startDate) != 10 || len(endDate) != 10 {
		startDate = defaultStart
		endDate = defaultEnd
	}

	ruleIDFilter, _ := strconv.ParseInt(ruleIDStr, 10, 64)

	query := `SELECT id, name FROM rules`
	args := []interface{}{}
	if ruleIDFilter > 0 {
		query += ` WHERE id=?`
		args = append(args, ruleIDFilter)
	}
	query += ` ORDER BY id`

	rows, err := db.DB.Query(query, args...)
	if err != nil {
		util.Fail(c, 500, err.Error())
		return
	}
	type ruleRow struct {
		id   int64
		name string
	}
	var rules []ruleRow
	for rows.Next() {
		var r ruleRow
		rows.Scan(&r.id, &r.name)
		rules = append(rules, r)
	}
	rows.Close()

	logDir := config.Global.Nginx.LogDir
	var entries []errorLogEntry

	for _, r := range rules {
		logPath := filepath.Join(logDir, fmt.Sprintf("rule_%d_access.log", r.id))
		lines := tailFileForDateRange(logPath, startDate, endDate, 20000)
		for _, line := range lines {
			m := reAccessLog.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			status, _ := strconv.Atoi(m[5])
			if status < 400 {
				continue
			}
			if codeFilter == "4xx" && status >= 500 {
				continue
			}
			if codeFilter == "5xx" && status < 500 {
				continue
			}

			bytes, _ := strconv.ParseInt(m[6], 10, 64)

			req := m[4]
			method, path := "-", req
			parts := strings.Fields(req)
			if len(parts) >= 2 {
				method = parts[0]
				path = parts[1]
			}

			entries = append(entries, errorLogEntry{
				Time:     nginxTimeToISO(m[2], m[3]),
				RuleID:   r.id,
				RuleName: r.name,
				IP:       m[1],
				Method:   method,
				Path:     path,
				Status:   status,
				Bytes:    bytes,
				UA:       m[7],
				Upstream: m[8],
			})
		}
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Time > entries[j].Time
	})

	util.OK(c, gin.H{"total": len(entries), "list": entries})
}

// ListRulesSimple 返回规则 id+name 列表，供出错日志筛选用
func ListRulesSimple(c *gin.Context) {
	rows, _ := db.DB.Query(`SELECT id, name FROM rules ORDER BY id`)
	defer rows.Close()
	list := []gin.H{}
	for rows.Next() {
		var id int64
		var name string
		rows.Scan(&id, &name)
		list = append(list, gin.H{"id": id, "name": name})
	}
	util.OK(c, list)
}
