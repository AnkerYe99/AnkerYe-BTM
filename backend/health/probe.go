package health

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"ankerye-flow/engine"
	"ankerye-flow/model"
)

type ProbeResult struct {
	OK      bool
	Latency int
	Err     string
}

func Probe(s *model.Server, r *model.Rule) ProbeResult {
	start := time.Now()
	// 使用 net.JoinHostPort 正确处理 IPv6 地址（自动加中括号）
	addr := net.JoinHostPort(s.Address, fmt.Sprint(s.Port))
	timeout := time.Duration(r.HCTimeout) * time.Second
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	switch r.Protocol {
	case "http", "https":
		// hc_host 优先；未填时自动取 server_name 第一个有效域名
		hcHost := r.HCHost
		if hcHost == "" {
			for _, d := range strings.Fields(r.ServerName) {
				if d != "_" && d != "" {
					hcHost = d
					break
				}
			}
		}
		scheme := r.UpstreamProtocol
		if scheme == "" {
			scheme = engine.DefaultUpstreamProtocol
		}
		var tlsConfig *tls.Config
		if scheme == "https" {
			sslName, err := engine.ResolveProxySSLName(r.ProxySSLName, r.ServerName)
			if err != nil {
				return ProbeResult{OK: false, Latency: int(time.Since(start).Milliseconds()), Err: "TLS SNI 配置无效"}
			}
			tlsConfig = &tls.Config{
				ServerName:         sslName,
				MinVersion:         tls.VersionTLS12,
				MaxVersion:         tls.VersionTLS13,
				InsecureSkipVerify: r.ProxySSLVerify == 0,
			}
			if r.ProxySSLVerify != 0 && r.ProxySSLTrustedCAPEM != "" {
				pool := x509.NewCertPool()
				if !pool.AppendCertsFromPEM([]byte(r.ProxySSLTrustedCAPEM)) {
					return ProbeResult{OK: false, Latency: int(time.Since(start).Milliseconds()), Err: "回源 CA 无效"}
				}
				tlsConfig.RootCAs = pool
			}
			if r.ProxySSLVerify != 0 && r.ProxySSLVerifyDepth > 0 {
				maxDepth := r.ProxySSLVerifyDepth
				tlsConfig.VerifyConnection = func(state tls.ConnectionState) error {
					for _, chain := range state.VerifiedChains {
						intermediates := len(chain) - 2 // 不计叶子证书和信任根
						if intermediates < 0 {
							intermediates = 0
						}
						if intermediates <= maxDepth {
							return nil
						}
					}
					return fmt.Errorf("回源证书链深度超过 %d", maxDepth)
				}
			}
		}
		return probeHTTP(addr, scheme, r.HCPath, hcHost, timeout, start, tlsConfig, scheme == "http")
	case "tcp":
		return probeTCP(addr, timeout, start)
	case "udp":
		return probeUDP(addr, timeout, start)
	case "tcpudp":
		// TCP+UDP 规则优先用 TCP 探测，失败则降级 UDP
		if res := probeTCP(addr, timeout, start); res.OK {
			return res
		}
		return probeUDP(addr, timeout, start)
	}
	return ProbeResult{OK: false, Err: "unknown protocol"}
}

func probeHTTP(addr, proto, path, hcHost string, timeout time.Duration, start time.Time, tlsConfig *tls.Config, allowTCPFallback bool) ProbeResult {
	if path == "" {
		path = "/"
	}
	scheme := "http"
	if proto == "https" {
		scheme = "https"
	}
	rawURL := fmt.Sprintf("%s://%s%s", scheme, addr, path)

	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // 不跟随重定向，3xx 直接算健康
		},
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
			DialContext:     (&net.Dialer{Timeout: timeout}).DialContext,
		},
	}
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return ProbeResult{OK: false, Latency: int(time.Since(start).Milliseconds()), Err: err.Error()}
	}
	if hcHost != "" {
		req.Host = hcHost
	}
	resp, err := client.Do(req)
	latency := int(time.Since(start).Milliseconds())
	if err != nil {
		// HTTP 层失败（对端在建连后关闭/EOF/重置，或按来源IP、Host 拒绝本次探测）——
		// 退回 TCP 存活探测：端口能建立连接即证明后端进程在运行、仅拒绝了这次探测请求，不算宕机。
		// 典型场景：共享后端对非白名单来源的真实 vhost 直接 close(444)，但对真实业务流量正常服务。
		if allowTCPFallback {
			if c, e := net.DialTimeout("tcp", addr, timeout); e == nil {
				c.Close()
				return ProbeResult{OK: true, Latency: latency}
			}
		}
		return ProbeResult{OK: false, Latency: latency, Err: err.Error()}
	}
	defer resp.Body.Close()
	// 任何 < 500 的 HTTP 应答都证明服务在运行（含 404：vhost 未配置/路径不存在属配置问题，非宕机）；
	// 仅 5xx（服务器内部错误）判为故障。
	if resp.StatusCode < 500 {
		return ProbeResult{OK: true, Latency: latency}
	}
	return ProbeResult{OK: false, Latency: latency, Err: fmt.Sprintf("status=%d", resp.StatusCode)}
}

func probeTCP(addr string, timeout time.Duration, start time.Time) ProbeResult {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	latency := int(time.Since(start).Milliseconds())
	if err != nil {
		return ProbeResult{OK: false, Latency: latency, Err: err.Error()}
	}
	conn.Close()
	return ProbeResult{OK: true, Latency: latency}
}

func probeUDP(addr string, timeout time.Duration, start time.Time) ProbeResult {
	conn, err := net.DialTimeout("udp", addr, timeout)
	latency := int(time.Since(start).Milliseconds())
	if err != nil {
		return ProbeResult{OK: false, Latency: latency, Err: err.Error()}
	}
	defer conn.Close()
	// UDP 无连接：发探测字节，等读返回
	conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte{0x00}); err != nil {
		return ProbeResult{OK: false, Latency: latency, Err: err.Error()}
	}
	buf := make([]byte, 512)
	_, err = conn.Read(buf)
	latency = int(time.Since(start).Milliseconds())
	if err != nil {
		// 超时视为通（UDP 服务可能无响应）
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return ProbeResult{OK: true, Latency: latency, Err: "timeout (assumed ok for udp)"}
		}
		// ICMP Unreachable 等明确错误 = 不通
		return ProbeResult{OK: false, Latency: latency, Err: err.Error()}
	}
	return ProbeResult{OK: true, Latency: latency}
}
