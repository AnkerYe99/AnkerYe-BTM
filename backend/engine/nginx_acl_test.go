package engine

import (
	"net"
	"strings"
	"testing"

	"ankerye-flow/model"
)

// 集成验证：ACL 指令要真的落在 server 块级、且在 location 之前，
// 这样 location 没有自带 allow/deny 时才会继承到整条规则。
func TestRenderHTTP_IncludesIPACL(t *testing.T) {
	httpsPort := 443
	r := &model.Rule{
		ID: 42, Name: "acl-test", Protocol: "http",
		ListenPort: 80, ListenStack: "v4",
		HTTPSEnabled: 1, HTTPSPort: &httpsPort, Domain: "a.example.com",
		ServerName: "a.example.com", LBMethod: "round_robin",
		IPACLMode: "allow", IPACLList: "118.143.68.96/28\n161.153.89.153",
	}
	out := renderHTTP(r, []model.Server{{Address: "10.0.0.1", Port: 8080, Weight: 1}})

	if strings.Count(out, "allow 118.143.68.96/28;") != 2 {
		t.Errorf("HTTP 和 HTTPS 两个 server 块都应带上 ACL，实际:\n%s", out)
	}
	locIdx := strings.Index(out, "location /")
	aclIdx := strings.Index(out, "allow 118.143.68.96/28;")
	if aclIdx < 0 || locIdx < 0 || aclIdx > locIdx {
		t.Errorf("ACL 必须在 location 之前（server 块级），实际:\n%s", out)
	}
	if !strings.Contains(out, "deny all;") {
		t.Errorf("白名单模式缺少 deny all，实际:\n%s", out)
	}

	// 关闭时不得残留任何 allow/deny
	r.IPACLMode = "off"
	if out := renderHTTP(r, []model.Server{{Address: "10.0.0.1", Port: 8080, Weight: 1}}); strings.Contains(out, "deny all;") {
		t.Errorf("关闭 ACL 后不应残留指令:\n%s", out)
	}
}

// 整体非法的输入必须一条都不通过
func TestParseIPACL_RejectsInvalid(t *testing.T) {
	evil := []string{
		"all",
		"unix:",
		"example.com",
		"999.1.1.1",
		"1.2.3.4/33",
		"2001:db8::/129",
		"1.2.3.4/abc",
		"../../etc/passwd",
		"$remote_addr",
	}
	for _, in := range evil {
		valid, invalid := ParseIPACL(in)
		if len(valid) > 0 {
			t.Errorf("危险输入被当成合法条目: %q -> %v", in, valid)
		}
		if len(invalid) == 0 {
			t.Errorf("危险输入未被标记为非法: %q", in)
		}
	}
}

// 核心安全属性：无论输入多恶意，生成的 nginx 指令行里只能出现 allow/deny + 合法 IP，
// 注入片段绝不能落成指令。
func TestRenderIPACL_NoInjection(t *testing.T) {
	evil := []string{
		"1.2.3.4; } server { listen 80",
		"1.2.3.4;\nreturn 200 'pwned';",
		"1.2.3.4;\nallow all;",
		"1.2.3.4 5.6.7.8; deny all",
		"1.2.3.4\n../../etc/passwd",
	}
	for _, mode := range []string{"allow", "deny"} {
		for _, in := range evil {
			out := renderIPACL(mode, in)
			for _, line := range strings.Split(out, "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue // 注释行不参与解析，非法内容落在这里是预期的
				}
				if !strings.HasPrefix(line, "allow ") && !strings.HasPrefix(line, "deny ") {
					t.Errorf("mode=%s 输入 %q 生成了非 allow/deny 指令: %q", mode, in, line)
					continue
				}
				arg := strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(line, "allow "), "deny "), ";")
				if arg != "all" && !isIPOrCIDR(arg) {
					t.Errorf("mode=%s 输入 %q 生成了非法参数: %q", mode, in, arg)
				}
			}
		}
	}
	// 非法条目必须留痕，不能静默丢弃
	out := renderIPACL("deny", "1.2.3.4\nexample.com")
	if !strings.Contains(out, "已忽略") || !strings.Contains(out, "example.com") {
		t.Errorf("被丢弃的非法条目未在配置中留痕:\n%s", out)
	}
}

func TestParseIPACL_AcceptsValid(t *testing.T) {
	in := "118.143.68.96/28\n161.153.89.153\n# 这是注释\n2001:db8::/32, 10.0.0.1\n\n  \n10.0.0.1"
	valid, invalid := ParseIPACL(in)
	if len(invalid) != 0 {
		t.Fatalf("合法输入被判为非法: %v", invalid)
	}
	want := []string{"118.143.68.96/28", "161.153.89.153", "2001:db8::/32", "10.0.0.1"}
	if len(valid) != len(want) {
		t.Fatalf("条目数不符，want %v, got %v", want, valid)
	}
	for i := range want {
		if valid[i] != want[i] {
			t.Errorf("第 %d 条: want %q, got %q", i, want[i], valid[i])
		}
	}
}

func TestRenderIPACL(t *testing.T) {
	// 关闭态不产生任何指令
	for _, mode := range []string{"off", "", "bogus"} {
		if out := renderIPACL(mode, "1.2.3.4"); out != "" {
			t.Errorf("mode=%q 不应生成配置，得到: %q", mode, out)
		}
	}
	// 名单为空时不生成半截配置（否则 allow 模式会只剩 deny all，把整条规则锁死）
	if out := renderIPACL("allow", "   \n # 只有注释\n"); out != "" {
		t.Errorf("空名单不应生成配置，得到: %q", out)
	}
	if out := renderIPACL("allow", "999.999.999.999"); out != "" {
		t.Errorf("全非法名单不应生成配置，得到: %q", out)
	}

	allow := renderIPACL("allow", "118.143.68.96/28\n161.153.89.153")
	if !strings.Contains(allow, "allow 118.143.68.96/28;") ||
		!strings.Contains(allow, "allow 161.153.89.153;") ||
		!strings.HasSuffix(strings.TrimRight(allow, "\n"), "deny all;") {
		t.Errorf("白名单模式生成有误:\n%s", allow)
	}

	deny := renderIPACL("deny", "1.2.3.4")
	if !strings.Contains(deny, "deny 1.2.3.4;") ||
		!strings.HasSuffix(strings.TrimRight(deny, "\n"), "allow all;") {
		t.Errorf("黑名单模式生成有误:\n%s", deny)
	}
}

// trustedSources 同时喂给 nginx 的 set_real_ip_from 和 isIPTrusted。
// 若某条写成裸 IP（漏了 /32），ParseCIDR 会失败，isIPTrusted 会静默跳过它——
// nginx 那边照样信任，判断就此错位且毫无报错。这个测试把格式钉死。
func TestTrustedSourcesWellFormed(t *testing.T) {
	if len(trustedSources) == 0 {
		t.Fatal("trustedSources 不应为空")
	}
	seen := map[string]bool{}
	for _, s := range trustedSources {
		if _, _, err := net.ParseCIDR(s.cidr); err != nil {
			t.Errorf("%q 不是合法 CIDR（裸 IP 要写成 /32）: %v", s.cidr, err)
		}
		if s.note == "" {
			t.Errorf("%q 缺少来源备注", s.cidr)
		}
		if seen[s.cidr] {
			t.Errorf("%q 重复", s.cidr)
		}
		seen[s.cidr] = true
	}
}

func TestIsIPTrusted(t *testing.T) {
	trusted := []string{"61.92.38.202", "10.1.2.3", "172.16.0.1", "161.153.89.153"}
	for _, ip := range trusted {
		if !isIPTrusted(ip) {
			t.Errorf("%s 应为可信来源", ip)
		}
	}
	// 1107 换过 IP，旧地址已作废，不该再被信任
	untrusted := []string{"42.2.33.138", "8.8.8.8", "118.143.68.98", "not-an-ip"}
	for _, ip := range untrusted {
		if isIPTrusted(ip) {
			t.Errorf("%s 不应为可信来源", ip)
		}
	}
}

func TestNormalizeACLMode(t *testing.T) {
	cases := map[string]string{
		"allow": "allow", "deny": "deny",
		"off": "off", "": "off", "ALLOW": "off", "junk": "off",
	}
	for in, want := range cases {
		if got := normalizeACLMode(in); got != want {
			t.Errorf("normalizeACLMode(%q) = %q, want %q", in, got, want)
		}
	}
}
