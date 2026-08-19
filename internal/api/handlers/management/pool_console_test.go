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
