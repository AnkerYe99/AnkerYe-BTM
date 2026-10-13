package handler

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func defaultExportRule() ruleForExport {
	return ruleForExport{
		ID: 1, Protocol: "http", UpstreamProtocol: "http", ProxySSLVerify: 1,
		ProxySSLVerifyDepth: 5, ProxyReadTimeout: 60,
	}
}

func TestRulesNeedHTTPSUpstreamV1(t *testing.T) {
	base := defaultExportRule()
	if rulesNeedHTTPSUpstreamV1([]ruleForExport{base}) {
		t.Fatal("default-only rule unexpectedly requires capability")
	}
	cases := []ruleForExport{base, base, base, base, base, base}
	cases[0].UpstreamProtocol = "https"
	cases[1].ProxySSLName = "origin.example.invalid"
	cases[2].ProxySSLVerify = 0
	cases[3].ProxySSLTrustedCAPEM = "ca"
	cases[4].ProxySSLVerifyDepth = 6
	cases[5].ProxyReadTimeout = 660
	for i, r := range cases {
		if !rulesNeedHTTPSUpstreamV1([]ruleForExport{r}) {
			t.Errorf("case %d did not require capability", i)
		}
	}
}

func TestCapabilityGateReturns409AndAcceptsNewNode(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := defaultExportRule()
	r.UpstreamProtocol = "https"

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/api/v1/sync/rules_export", nil)
	if enforceRuleSyncCapability(c, []ruleForExport{r}) {
		t.Fatal("old node was allowed to receive active new fields")
	}
	if w.Code != 409 || !strings.Contains(w.Body.String(), "upgrade_required") {
		t.Fatalf("unexpected gate response: status=%d body=%s", w.Code, w.Body.String())
	}

	w = httptest.NewRecorder()
	c, _ = gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/api/v1/sync/rules_export?caps=https_upstream_v1", nil)
	if !enforceRuleSyncCapability(c, []ruleForExport{r}) {
		t.Fatal("capable node was rejected")
	}
}
