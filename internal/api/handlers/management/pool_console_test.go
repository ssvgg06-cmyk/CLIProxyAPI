package management

import (
	"strings"
	"testing"
)

func TestPoolConsoleDoesNotAdvancePoolOrUseUnsafeDOMSinks(t *testing.T) {
	for _, forbidden := range []string{
		`getJSON("/auth-files`,
		"localStorage",
		"sessionStorage",
		"indexedDB",
		"innerHTML",
		"outerHTML",
		"insertAdjacentHTML",
		"document.write",
	} {
		if strings.Contains(poolConsoleHTML, forbidden) {
			t.Fatalf("pool console contains forbidden token %q", forbidden)
		}
	}
	if !strings.Contains(poolConsoleHTML, `getJSON("/pool-log-account/`) {
		t.Fatal("pool console must resolve associated accounts through the dedicated safe endpoint")
	}
	if strings.Count(poolConsoleHTML, `$("key").value = ""`) < 2 {
		t.Fatal("pool console does not clear the password field after unlock and lock")
	}
}

func TestPoolConsoleUsesCPAManagementVisualLanguage(t *testing.T) {
	for _, required := range []string{
		`--cpa-surface-subtle: #f6f6f6`,
		`--cpa-border: #e5e5e5`,
		`--sidebar-width: 216px`,
		`class="sidebar"`,
		`aria-current="page"`,
		`日志链路分析`,
		`CLI Proxy API 管理控制台`,
		`关联账号采用稳定映射`,
		`不代表真实上游处理凭据`,
	} {
		if !strings.Contains(poolConsoleHTML, required) {
			t.Fatalf("pool console is missing CPA visual contract %q", required)
		}
	}
	for _, obsolete := range []string{
		`--bg: #0d1117`,
		`--accent: #4493f8`,
		`Credential Pool Log Console`,
	} {
		if strings.Contains(poolConsoleHTML, obsolete) {
			t.Fatalf("pool console still contains obsolete terminal styling %q", obsolete)
		}
	}
}
