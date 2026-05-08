package engine

import (
	"bufio"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"ankerye-flow/config"
	"ankerye-flow/db"
)

const defaultCaptureMaxBytes int64 = 5 * 1024 * 1024

var ruleIDFromFile = regexp.MustCompile(`rule_(\d+)_capture\.log$`)

// StartCaptureRotator 每 1 分钟检测一次所有 rule_X_capture.log，
// 超过规则配置的 capture_max_size 则尾部保留（裁掉前面老数据）。
func StartCaptureRotator() {
	log.Printf("[capture-rotator] started, check=1m, default_max=%d MB", defaultCaptureMaxBytes/1024/1024)
	for {
		time.Sleep(1 * time.Minute)
		trimAllCaptureLogs()
	}
}

func trimAllCaptureLogs() {
	pattern := filepath.Join(config.Global.Nginx.LogDir, "rule_*_capture.log")
	files, _ := filepath.Glob(pattern)
	if len(files) == 0 {
		return
	}
	trimmed := 0
	for _, f := range files {
		maxBytes := captureLimitForFile(f)
		if trimCaptureLog(f, maxBytes) {
			trimmed++
		}
	}
	if trimmed > 0 {
		_ = exec.Command("nginx", "-s", "reopen").Run()
		log.Printf("[capture-rotator] trimmed %d capture logs", trimmed)
	}
}

// captureLimitForFile 从文件名中解析 rule_id，查询 DB 中该规则的 capture_max_size。
func captureLimitForFile(path string) int64 {
	m := ruleIDFromFile.FindStringSubmatch(filepath.Base(path))
	if len(m) < 2 {
		return defaultCaptureMaxBytes
	}
	ruleID, _ := strconv.ParseInt(m[1], 10, 64)
	if ruleID <= 0 {
		return defaultCaptureMaxBytes
	}
	var sizeStr string
	db.DB.QueryRow(`SELECT IFNULL(capture_max_size,'5M') FROM rules WHERE id=?`, ruleID).Scan(&sizeStr)
	return parseSizeStr(sizeStr)
}

// parseSizeStr 解析 "5M" / "10M" / "100M" / "1G" 等字符串，返回字节数。
func parseSizeStr(s string) int64 {
	s = strings.TrimSpace(strings.ToUpper(s))
	if s == "" {
		return defaultCaptureMaxBytes
	}
	unit := int64(1)
	if strings.HasSuffix(s, "G") {
		unit = 1024 * 1024 * 1024
		s = s[:len(s)-1]
	} else if strings.HasSuffix(s, "M") {
		unit = 1024 * 1024
		s = s[:len(s)-1]
	} else if strings.HasSuffix(s, "K") {
		unit = 1024
		s = s[:len(s)-1]
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 {
		return defaultCaptureMaxBytes
	}
	return n * unit
}

// trimCaptureLog 若文件超过 maxBytes，截掉前面只保留尾部 maxBytes 字节。
func trimCaptureLog(path string, maxBytes int64) bool {
	st, err := os.Stat(path)
	if err != nil || st.Size() <= maxBytes {
		return false
	}

	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	if _, err := f.Seek(-maxBytes, io.SeekEnd); err != nil {
		return false
	}

	br := bufio.NewReaderSize(f, 64*1024)
	if _, err := br.ReadBytes('\n'); err != nil {
		return false
	}

	tmp := path + ".tmp"
	out, err := os.Create(tmp)
	if err != nil {
		return false
	}
	if _, err := io.Copy(out, br); err != nil {
		_ = out.Close()
		_ = os.Remove(tmp)
		return false
	}
	_ = out.Close()

	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return false
	}
	return true
}
