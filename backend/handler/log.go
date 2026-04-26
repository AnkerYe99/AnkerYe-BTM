package handler

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"ankerye-flow/config"
	"ankerye-flow/middleware"
	"ankerye-flow/util"
)

// DownloadRuleLog 下载规则日志文件
func DownloadRuleLog(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	logType := c.DefaultQuery("type", "access")
	var logPath string
	if logType == "stream" {
		logPath = filepath.Join(config.Global.Nginx.LogDir, fmt.Sprintf("rule_%d_stream.log", id))
	} else {
		logPath = filepath.Join(config.Global.Nginx.LogDir, fmt.Sprintf("rule_%d_access.log", id))
	}
	info, err := os.Stat(logPath)
	if err != nil {
		util.Fail(c, 404, "日志文件不存在")
		return
	}
	filename := filepath.Base(logPath)
	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	c.Header("Content-Type", "text/plain; charset=utf-8")
	c.Header("Content-Length", fmt.Sprintf("%d", info.Size()))
	c.File(logPath)
}

// StreamRuleLogs streams the access log of a rule via SSE.
// Auth is via ?token= query param because EventSource doesn't support headers.
func StreamRuleLogs(c *gin.Context) {
	// Validate JWT from query param
	tokenStr := c.Query("token")
	if tokenStr == "" {
		c.String(401, "unauthorized")
		return
	}
	claims := &middleware.Claims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
		return []byte(config.Global.Server.JWTSecret), nil
	})
	if err != nil || !token.Valid {
		c.String(401, "token invalid")
		return
	}

	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)

	// Determine log file: access log for http, stream log for tcp/udp
	logType := c.DefaultQuery("type", "access")
	var logPath string
	if logType == "stream" {
		logPath = filepath.Join(config.Global.Nginx.LogDir, fmt.Sprintf("rule_%d_stream.log", id))
	} else {
		logPath = filepath.Join(config.Global.Nginx.LogDir, fmt.Sprintf("rule_%d_access.log", id))
	}

	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("X-Accel-Buffering", "no") // disable nginx proxy buffering

	flusher, ok := c.Writer.(http.Flusher)
	if !ok {
		return
	}

	send := func(line string) {
		// Escape any newlines in the log line
		line = strings.ReplaceAll(line, "\n", " ")
		fmt.Fprintf(c.Writer, "data: %s\n\n", line)
	}

	// Send last 100 lines immediately on connect
	if out, err := exec.Command("tail", "-n", "100", logPath).Output(); err == nil {
		lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
		for _, l := range lines {
			if l != "" {
				send(l)
			}
		}
	} else {
		send("--- 暂无日志，等待请求进入... ---")
	}
	flusher.Flush()

	// Track file offset for incremental reads
	var offset int64
	if f, err := os.Open(logPath); err == nil {
		offset, _ = f.Seek(0, 2) // seek to end
		f.Close()
	}

	ctx := c.Request.Context()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			f, err := os.Open(logPath)
			if err != nil {
				continue
			}
			fi, _ := f.Stat()
			if fi.Size() <= offset {
				f.Close()
				continue
			}
			f.Seek(offset, 0)
			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				send(scanner.Text())
			}
			offset, _ = f.Seek(0, 1)
			f.Close()
			flusher.Flush()
		}
	}
}
