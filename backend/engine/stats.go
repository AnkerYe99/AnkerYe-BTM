package engine

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"syscall"
	"time"

	"nginxflow/config"
	"nginxflow/db"
)

var (
	// HTTP: combined + $upstream_addr 末尾
	reCombined = regexp.MustCompile(
		`^\S+ - \S+ \[(\d{2}/\w+/\d{4}):\d{2}:\d{2}:\d{2} [+-]\d{4}\] "[^"]*" (\d{3}) (\d+) "[^"]*" "[^"]*" (\S+)`)
	// Stream: basic + "$upstream_addr" 末尾（quoted）
	reBasic = regexp.MustCompile(
		`^\S+ \[(\d{2}/\w+/\d{4}):\d{2}:\d{2}:\d{2} [+-]\d{4}\] \S+ (\d+) (\d+) \d+ [\d.]+ "([^"]*)"`)
	monthMap = map[string]string{
		"Jan": "01", "Feb": "02", "Mar": "03", "Apr": "04",
		"May": "05", "Jun": "06", "Jul": "07", "Aug": "08",
		"Sep": "09", "Oct": "10", "Nov": "11", "Dec": "12",
	}
)

type dayStat struct {
	requests, bytesOut         int64
	s1xx, s2xx, s3xx, s4xx, s5xx int64
}

// nginxDateToISO 把 "24/Apr/2026" 转成 "2026-04-24"
func nginxDateToISO(s string) string {
	parts := make([]string, 0, 3)
	cur := ""
	for _, c := range s {
		if c == '/' {
			parts = append(parts, cur)
			cur = ""
		} else {
			cur += string(c)
		}
	}
	parts = append(parts, cur)
	if len(parts) != 3 {
		return s
	}
	m := monthMap[parts[1]]
	if m == "" {
		m = parts[1]
	}
	return fmt.Sprintf("%s-%s-%02s", parts[2], m, parts[0])
}

func fileInode(path string) uint64 {
	info, err := os.Stat(path)
	if err != nil {
		return 0
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0
	}
	return st.Ino
}

// loadServerMap 返回 rule 下 "addr:port" → server_id 的映射
func loadServerMap(ruleID int64) map[string]int64 {
	m := map[string]int64{}
	rows, err := db.DB.Query(`SELECT id, address, port FROM upstream_servers WHERE rule_id=?`, ruleID)
	if err != nil {
		return m
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var addr string
		var port int
		rows.Scan(&id, &addr, &port)
		m[fmt.Sprintf("%s:%d", addr, port)] = id
	}
	return m
}

// resolveUpstream 把 nginx upstream_addr 字段（可能带重试，如 "a:80 : b:80"）解析成最后一跳的 "host:port"
func resolveUpstream(raw string) string {
	if raw == "" || raw == "-" {
		return ""
	}
	// 多次重试以 " : " 分隔，取最后一个
	parts := regexp.MustCompile(` : `).Split(raw, -1)
	last := parts[len(parts)-1]
	// strip brackets for IPv6 [::1]:80 → "::1:80" is wrong; keep original key format
	host, portStr, err := net.SplitHostPort(last)
	if err != nil {
		return ""
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%s:%d", host, port)
}

func updateDayStat(days map[string]*dayStat, date string, status int, bytesOut int64) {
	if _, ok := days[date]; !ok {
		days[date] = &dayStat{}
	}
	s := days[date]
	s.requests++
	s.bytesOut += bytesOut
	switch status / 100 {
	case 1:
		s.s1xx++
	case 2:
		s.s2xx++
	case 3:
		s.s3xx++
	case 4:
		s.s4xx++
	case 5:
		s.s5xx++
	}
}

func flushRuleStats(ruleID int64, days map[string]*dayStat) {
	for date, s := range days {
		if s.requests == 0 {
			continue
		}
		db.AsyncExec(`INSERT INTO rule_stats(rule_id,date,requests,bytes_out,s1xx,s2xx,s3xx,s4xx,s5xx)
			VALUES(?,?,?,?,?,?,?,?,?)
			ON CONFLICT(rule_id,date) DO UPDATE SET
			requests=requests+excluded.requests, bytes_out=bytes_out+excluded.bytes_out,
			s1xx=s1xx+excluded.s1xx, s2xx=s2xx+excluded.s2xx, s3xx=s3xx+excluded.s3xx,
			s4xx=s4xx+excluded.s4xx, s5xx=s5xx+excluded.s5xx`,
			ruleID, date, s.requests, s.bytesOut,
			s.s1xx, s.s2xx, s.s3xx, s.s4xx, s.s5xx)
	}
}

func flushServerStats(serverDays map[int64]map[string]*dayStat) {
	for serverID, days := range serverDays {
		for date, s := range days {
			if s.requests == 0 {
				continue
			}
			db.AsyncExec(`INSERT INTO server_stats(server_id,date,requests,bytes_out,s1xx,s2xx,s3xx,s4xx,s5xx)
				VALUES(?,?,?,?,?,?,?,?,?)
				ON CONFLICT(server_id,date) DO UPDATE SET
				requests=requests+excluded.requests, bytes_out=bytes_out+excluded.bytes_out,
				s1xx=s1xx+excluded.s1xx, s2xx=s2xx+excluded.s2xx, s3xx=s3xx+excluded.s3xx,
				s4xx=s4xx+excluded.s4xx, s5xx=s5xx+excluded.s5xx`,
				serverID, date, s.requests, s.bytesOut,
				s.s1xx, s.s2xx, s.s3xx, s.s4xx, s.s5xx)
		}
	}
}

func parseLogFile(ruleID int64, logFile string, isStream bool, serverMap map[string]int64) {
	var savedInode uint64
	var savedOffset int64
	db.DB.QueryRow(`SELECT inode, offset FROM log_parse_state WHERE log_file=?`, logFile).
		Scan(&savedInode, &savedOffset)

	curInode := fileInode(logFile)
	if curInode == 0 {
		return
	}

	f, err := os.Open(logFile)
	if err != nil {
		return
	}
	defer f.Close()

	if curInode != savedInode {
		savedOffset = 0
	}
	f.Seek(savedOffset, 0)

	days := map[string]*dayStat{}
	serverDays := map[int64]map[string]*dayStat{}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 64*1024)

	for scanner.Scan() {
		line := scanner.Text()
		var date, upstreamRaw string
		var status int
		var bytesOut int64

		if isStream {
			m := reBasic.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			date = nginxDateToISO(m[1])
			status, _ = strconv.Atoi(m[2])
			bytesOut, _ = strconv.ParseInt(m[3], 10, 64)
			upstreamRaw = m[4]
		} else {
			m := reCombined.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			date = nginxDateToISO(m[1])
			status, _ = strconv.Atoi(m[2])
			bytesOut, _ = strconv.ParseInt(m[3], 10, 64)
			upstreamRaw = m[4]
		}

		updateDayStat(days, date, status, bytesOut)

		if key := resolveUpstream(upstreamRaw); key != "" {
			if sid, ok := serverMap[key]; ok {
				if serverDays[sid] == nil {
					serverDays[sid] = map[string]*dayStat{}
				}
				updateDayStat(serverDays[sid], date, status, bytesOut)
			}
		}
	}

	newOffset, _ := f.Seek(0, 1)
	db.AsyncExec(`INSERT INTO log_parse_state(log_file,inode,offset) VALUES(?,?,?)
		ON CONFLICT(log_file) DO UPDATE SET inode=excluded.inode, offset=excluded.offset`,
		logFile, curInode, newOffset)

	flushRuleStats(ruleID, days)
	flushServerStats(serverDays)
}

func parseAllLogs() {
	rows, err := db.DB.Query(`SELECT id, protocol FROM rules WHERE status=1 ORDER BY id`)
	if err != nil {
		return
	}
	var rules []struct {
		id    int64
		proto string
	}
	for rows.Next() {
		var id int64
		var proto string
		rows.Scan(&id, &proto)
		rules = append(rules, struct {
			id    int64
			proto string
		}{id, proto})
	}
	rows.Close()

	logDir := config.Global.Nginx.LogDir
	for _, r := range rules {
		sm := loadServerMap(r.id)
		switch r.proto {
		case "http", "https":
			parseLogFile(r.id, fmt.Sprintf("%s/rule_%d_access.log", logDir, r.id), false, sm)
		case "tcp", "udp", "tcpudp":
			parseLogFile(r.id, fmt.Sprintf("%s/rule_%d_stream.log", logDir, r.id), true, sm)
		}
	}
}

// StartStatsWorker 每分钟增量扫描 nginx 日志并写入统计
func StartStatsWorker() {
	go func() {
		time.Sleep(10 * time.Second)
		for {
			parseAllLogs()
			time.Sleep(60 * time.Second)
		}
	}()
}
