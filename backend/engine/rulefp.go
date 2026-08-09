package engine

import (
	"fmt"
	"io"
)

// 规则指纹（fingerprint）—— 主从同步靠它比对 MD5 决定要不要拉取全量数据。
//
// ⚠️ 这里是主从两侧唯一的格式定义，两边都必须调用本文件的函数，不要各写一份 Fprintf。
// 历史教训：主节点(handler/sync.go)和从节点(engine/sync_slave.go)原本各维护一份格式串，
// 加 hc_host 时只改了主节点那份，两边指纹从此永远不相等——从节点每一轮都判定"有变化"、
// 每次都全量拉取。因为表现是"多同步"而不是"不同步"，这个 bug 一直没被发现，
// 反过来又掩盖了新增字段忘记进指纹的问题（改字段→指纹不变→真的不同步）。
//
// 新增规则字段时：加进 RuleFP 并写进 WriteRuleFP，主从会自动一起变。

// RuleFP 是参与指纹计算的规则字段集合。
// 注意用 SslCertDomain 而非 ssl_cert_id——主从的证书自增 id 不一定相同，域名才是稳定标识。
type RuleFP struct {
	ID             int64
	Name           string
	Protocol       string
	ListenPort     int64
	ListenStack    string
	HTTPSEnabled   int64
	HTTPSPort      int64
	ServerName     string
	LBMethod       string
	SSLCertDomain  string
	SSLRedirect    int64
	HCEnabled      int64
	HCInterval     int64
	HCTimeout      int64
	HCPath         string
	HCHost         string
	HCFall         int64
	HCRise         int64
	LogMaxSize     string
	CaptureMaxSize string
	CustomConfig   string
	CaptureBody    int64
	IPACLMode      string
	IPACLList      string
	Status         int64
}

// ServerFP 是参与指纹计算的上游节点字段集合。
type ServerFP struct {
	Address string
	Port    int64
	Weight  int64
	State   string
}

// WriteRuleFP 写入一条规则的规范化指纹行。规则按 id ASC 排序后逐条写入。
func WriteRuleFP(w io.Writer, r RuleFP) {
	fmt.Fprintf(w, "R:%d|%q|%q|%d|%q|%d|%d|%q|%q|%q|%d|%d|%d|%d|%q|%q|%d|%d|%q|%q|%q|%d|%q|%q|%d\n",
		r.ID, r.Name, r.Protocol, r.ListenPort, r.ListenStack,
		r.HTTPSEnabled, r.HTTPSPort, r.ServerName, r.LBMethod,
		r.SSLCertDomain, r.SSLRedirect, r.HCEnabled, r.HCInterval, r.HCTimeout,
		r.HCPath, r.HCHost, r.HCFall, r.HCRise, r.LogMaxSize, r.CaptureMaxSize,
		r.CustomConfig, r.CaptureBody, r.IPACLMode, r.IPACLList, r.Status)
}

// WriteServerFP 写入一个上游节点的指纹行，紧跟其所属规则行之后，按 address ASC, port ASC 排序。
//
// ⚠️ state 只区分 disabled / 非 disabled，不能把 up/down 原样写进去：
// up/down 是各节点本地健康检查的运行时结果，天然会不一样——最典型的是 127.0.0.1 这类地址，
// 它在每台节点上指向的是各自本机的服务，探测结果必然不同。
// 一旦 up/down 进了指纹，主从就永远不相等：从节点每轮全量拉 → 覆盖本地 state →
// 本地健康检查又改回来 → 下一轮继续拉，形成永不收敛的震荡。
// 而 disabled 是人工配置、需要跨节点一致，必须参与比对。
func WriteServerFP(w io.Writer, s ServerFP) {
	state := s.State
	if state != "disabled" {
		state = "enabled"
	}
	fmt.Fprintf(w, "S:%q|%d|%d|%q\n", s.Address, s.Port, s.Weight, state)
}
