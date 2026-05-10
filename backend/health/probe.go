package health

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"time"

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
		// SSL 卸载模式下后端是 HTTP，所以始终用 HTTP 探测
		return probeHTTP(addr, "http", r.HCPath, r.HCHost, timeout, start)
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

func probeHTTP(addr, proto, path, hcHost string, timeout time.Duration, start time.Time) ProbeResult {
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
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			DialContext: (&net.Dialer{Timeout: timeout}).DialContext,
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
		return ProbeResult{OK: false, Latency: latency, Err: err.Error()}
	}
	defer resp.Body.Close()
	// 2xx / 3xx = 在线；4xx / 5xx = 故障（4xx 通常意味着 vhost 未配置或服务未就绪）
	if resp.StatusCode < 400 {
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
