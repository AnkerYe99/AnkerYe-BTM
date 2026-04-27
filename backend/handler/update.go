package handler

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"time"

	"github.com/gin-gonic/gin"

	"ankerye-flow/db"
	"ankerye-flow/util"
)

const (
	githubAPI   = "https://api.github.com"
	githubRepo  = "AnkerYe99/AnkerYe-BTM"
	giteaRepo   = "anker/AnkerYe-BTM"
	installPath = "/opt/AnkerYe-BTM/ankerye-flow-server"
)

func binaryName() string {
	switch runtime.GOARCH {
	case "arm64":
		return "ankerye-flow-server-arm64"
	default:
		return "ankerye-flow-server-amd64"
	}
}

var updateHTTPClient = &http.Client{Timeout: 30 * time.Second}

type releaseAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}
type releaseInfo struct {
	TagName string         `json:"tag_name"`
	Body    string         `json:"body"`
	Assets  []releaseAsset `json:"assets"`
}

// updateSource 返回 (apiBase, repo, sourceLabel)
// 优先使用用户在 system_settings 配置的内网 Gitea，否则 GitHub
func updateSource() (apiBase, repo, label string) {
	var giteaURL string
	db.DB.QueryRow(`SELECT v FROM system_settings WHERE k='update_gitea_url'`).Scan(&giteaURL)
	if giteaURL != "" {
		probe := giteaURL + "/api/v1/repos/" + giteaRepo
		resp, err := updateHTTPClient.Get(probe)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return giteaURL, giteaRepo, "Gitea"
			}
		}
	}
	return githubAPI, githubRepo, "GitHub"
}

func fetchRelease(apiBase, repo string) (*releaseInfo, error) {
	var url string
	if apiBase == githubAPI {
		url = fmt.Sprintf("%s/repos/%s/releases/latest", apiBase, repo)
	} else {
		url = fmt.Sprintf("%s/api/v1/repos/%s/releases/latest", apiBase, repo)
	}
	resp, err := updateHTTPClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("release API 返回 %d，请确认已创建 Release", resp.StatusCode)
	}
	var r releaseInfo
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, err
	}
	if r.TagName == "" {
		return nil, fmt.Errorf("未找到任何 Release，请先在仓库中发布版本")
	}
	return &r, nil
}

func assetURL(r *releaseInfo) string {
	name := binaryName()
	for _, a := range r.Assets {
		if a.Name == name {
			return a.BrowserDownloadURL
		}
	}
	return ""
}

// CheckUpdate GET /api/v1/update/check
func CheckUpdate(c *gin.Context) {
	apiBase, repo, label := updateSource()
	r, err := fetchRelease(apiBase, repo)
	if err != nil {
		util.Fail(c, 500, err.Error())
		return
	}
	dl := assetURL(r)
	if dl == "" {
		util.Fail(c, 400, "Release 中未找到 "+binaryName()+" 二进制，请先上传构建产物")
		return
	}

	current := currentVersion()
	util.OK(c, gin.H{
		"current":    current,
		"latest":     r.TagName,
		"has_update": current != r.TagName,
		"notes":      r.Body,
		"source":     label,
	})
}

// ApplyUpdate POST /api/v1/update/apply
func ApplyUpdate(c *gin.Context) {
	apiBase, repo, _ := updateSource()
	r, err := fetchRelease(apiBase, repo)
	if err != nil {
		util.Fail(c, 500, err.Error())
		return
	}
	dl := assetURL(r)
	if dl == "" {
		util.Fail(c, 400, "Release 中未找到 "+binaryName()+" 二进制")
		return
	}

	// 下载新二进制到临时路径
	tmpPath := fmt.Sprintf("/tmp/ankerye-btm-update-%d", time.Now().Unix())
	if err := downloadBinary(dl, tmpPath); err != nil {
		util.Fail(c, 500, "下载失败: "+err.Error())
		return
	}

	// 生成替换脚本：sleep 让当前请求先正常返回，再触发 systemd 重启
	script := fmt.Sprintf(`#!/bin/bash
sleep 2
cp "%s" "%s"
chmod +x "%s"
rm -f "%s" "$0"
systemctl restart AnkerYe-BTM
`, tmpPath, installPath, installPath, tmpPath)

	scriptPath := "/tmp/ankerye-btm-do-update.sh"
	if err := os.WriteFile(scriptPath, []byte(script), 0755); err != nil {
		os.Remove(tmpPath)
		util.Fail(c, 500, "写入更新脚本失败: "+err.Error())
		return
	}

	// 记录即将安装的版本
	db.DB.Exec(`INSERT OR REPLACE INTO system_settings(k,v) VALUES('app_version',?)`, r.TagName)

	// 后台异步执行，不等待
	cmd := exec.Command("bash", scriptPath)
	if err := cmd.Start(); err != nil {
		os.Remove(tmpPath)
		os.Remove(scriptPath)
		util.Fail(c, 500, "启动更新进程失败: "+err.Error())
		return
	}
	log.Printf("[update] 开始升级到 %s，pid=%d", r.TagName, cmd.Process.Pid)

	util.OK(c, gin.H{
		"msg":     fmt.Sprintf("正在升级到 %s，服务将在约 3 秒后自动重启，请刷新页面", r.TagName),
		"version": r.TagName,
	})
}

func downloadBinary(url, dest string) error {
	dlClient := &http.Client{Timeout: 10 * time.Minute}
	resp, err := dlClient.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	f, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, resp.Body)
	return err
}

func currentVersion() string {
	var v string
	db.DB.QueryRow(`SELECT v FROM system_settings WHERE k='app_version'`).Scan(&v)
	if v == "" {
		v = "unknown"
	}
	return v
}

// GetVersion GET /api/v1/version（无需鉴权，供安装脚本等使用）
func GetVersion(c *gin.Context) {
	util.OK(c, gin.H{"version": currentVersion()})
}
