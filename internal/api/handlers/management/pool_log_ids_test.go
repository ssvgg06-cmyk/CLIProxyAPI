package management

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
)

const (
	poolTestCanonicalRequestID = "synthetic-newapi-primary-request-0001"
	poolTestRealUpstreamID     = "synthetic-newapi-upstream-request-0001"
	poolTestCPAUpstreamID      = "req_016v2dZy7hjW41BibIX3nZZT"
)

func TestProjectCPAUpstreamRequestIDUsesStableDomainSeparatedBase62(t *testing.T) {
	got := projectCPAUpstreamRequestID(poolTestCanonicalRequestID)
	if got != poolTestCPAUpstreamID {
		t.Fatalf("projected CPA upstream request ID = %q, want %q", got, poolTestCPAUpstreamID)
	}
	if len(got) != len(cpaUpstreamRequestIDPrefix)+cpaRequestIDBase62Width {
		t.Fatalf("projected CPA upstream request ID length = %d", len(got))
	}
	if projectCPAUpstreamRequestID(poolTestCanonicalRequestID) != got {
		t.Fatal("projection changed for the same canonical request ID")
	}
	if projectCPAUpstreamRequestID(poolTestCanonicalRequestID+"x") == got {
		t.Fatal("different canonical request IDs produced the same test projection")
	}
	if projectCPAUpstreamRequestID("") != "" {
		t.Fatal("empty canonical request ID must not produce a presentation ID")
	}
	for _, character := range strings.TrimPrefix(got, cpaUpstreamRequestIDPrefix) {
		if !strings.ContainsRune(cpaRequestIDBase62Alphabet, character) {
			t.Fatalf("projection contains non-Base62 character %q", character)
		}
	}
}

func TestEncodeCPARequestIDBase62LeftPadsToTwentyTwoDigits(t *testing.T) {
	if got := encodeCPARequestIDBase62(make([]byte, 16)); got != strings.Repeat("0", cpaRequestIDBase62Width) {
		t.Fatalf("zero encoding = %q", got)
	}
	if got := encodeCPARequestIDBase62([]byte{1}); got != strings.Repeat("0", cpaRequestIDBase62Width-1)+"1" {
		t.Fatalf("one encoding = %q", got)
	}
}

func TestProjectCPAUpstreamRequestIDLargeSampleIsUniqueAndWellFormed(t *testing.T) {
	pattern := regexp.MustCompile(`^req_01[A-Za-z0-9]{22}$`)
	seen := make(map[string]string, 10000)
	for index := 0; index < 10000; index++ {
		canonical := fmt.Sprintf("newapi-request-%05d", index)
		projected := projectCPAUpstreamRequestID(canonical)
		if !pattern.MatchString(projected) {
			t.Fatalf("projection %q for %q has the wrong format", projected, canonical)
		}
		if previous, duplicate := seen[projected]; duplicate {
			t.Fatalf("projection collision for %q and %q: %s", previous, canonical, projected)
		}
		seen[projected] = canonical
	}
}

func TestPoolLogEntryCPAIdentifiersPreferRealUpstreamAndFallback(t *testing.T) {
	entry := poolLogEntry{RequestID: poolTestCanonicalRequestID, UpstreamID: poolTestRealUpstreamID}
	if got := entry.cpaRequestID(); got != poolTestRealUpstreamID {
		t.Fatalf("CPA request ID = %q, want real upstream %q", got, poolTestRealUpstreamID)
	}
	if got := entry.cpaUpstreamRequestID(); got != poolTestCPAUpstreamID {
		t.Fatalf("CPA upstream request ID = %q, want %q", got, poolTestCPAUpstreamID)
	}

	entry.UpstreamID = ""
	if got := entry.cpaRequestID(); got != poolTestCanonicalRequestID {
		t.Fatalf("CPA request ID fallback = %q, want canonical %q", got, poolTestCanonicalRequestID)
	}
}

func TestPoolLogPayloadKeepsSourceIDsWhileTextUsesCPAProjection(t *testing.T) {
	entry := poolLogEntry{
		Timestamp:  poolTestNow.Unix(),
		Level:      "INFO",
		Message:    "request completed",
		Source:     "newapi",
		RequestID:  poolTestCanonicalRequestID,
		UpstreamID: poolTestRealUpstreamID,
		Model:      "claude-opus-5",
		Status:     200,
	}

	payload := poolLogEntriesPayload([]poolLogEntry{entry})[0]
	checks := map[string]string{
		"request_id":              poolTestCanonicalRequestID,
		"upstream_request_id":     poolTestRealUpstreamID,
		"cpa_request_id":          poolTestRealUpstreamID,
		"cpa_upstream_request_id": poolTestCPAUpstreamID,
	}
	for field, want := range checks {
		if got, ok := payload[field].(string); !ok || got != want {
			t.Fatalf("payload[%q] = %#v, want %q", field, payload[field], want)
		}
	}

	line := entry.Line()
	for _, fragment := range []string{
		`request_id="` + poolTestRealUpstreamID + `"`,
		`upstream_request_id="` + poolTestCPAUpstreamID + `"`,
		`newapi_request_id="` + poolTestCanonicalRequestID + `"`,
		`newapi_upstream_request_id="` + poolTestRealUpstreamID + `"`,
	} {
		if !strings.Contains(line, fragment) {
			t.Fatalf("raw line %q is missing %q", line, fragment)
		}
	}

	body := poolRequestLogBody(entry)
	for _, fragment := range []string{
		"request_id: " + poolTestRealUpstreamID,
		"upstream_request_id: " + poolTestCPAUpstreamID,
		"newapi_request_id: " + poolTestCanonicalRequestID,
		"newapi_upstream_request_id: " + poolTestRealUpstreamID,
	} {
		if !strings.Contains(body, fragment) {
			t.Fatalf("download body is missing %q", fragment)
		}
	}

	changedUpstream := entry
	changedUpstream.UpstreamID = "another-real-upstream-id"
	if poolRequestLogName(entry) != poolRequestLogName(changedUpstream) {
		t.Fatal("request-log download locator stopped using the canonical New API request ID")
	}
}

func TestPoolLogProjectionFallsBackWhenNewAPIUpstreamIDIsEmpty(t *testing.T) {
	entry := poolLogEntry{
		Timestamp: poolTestNow.Unix(),
		Level:     "INFO",
		Message:   "request completed",
		Source:    "newapi",
		RequestID: poolTestCanonicalRequestID,
	}
	payload := poolLogEntriesPayload([]poolLogEntry{entry})[0]
	if got := payload["cpa_request_id"]; got != poolTestCanonicalRequestID {
		t.Fatalf("CPA request ID fallback = %#v, want %q", got, poolTestCanonicalRequestID)
	}
	if got := payload["upstream_request_id"]; got != "" {
		t.Fatalf("source upstream request ID = %#v, want empty", got)
	}
	for _, fragment := range []string{
		`request_id="` + poolTestCanonicalRequestID + `"`,
		`upstream_request_id="` + poolTestCPAUpstreamID + `"`,
		`newapi_request_id="` + poolTestCanonicalRequestID + `"`,
		`newapi_upstream_request_id=""`,
	} {
		if !strings.Contains(entry.Line(), fragment) {
			t.Fatalf("fallback raw line %q is missing %q", entry.Line(), fragment)
		}
	}
	for _, fragment := range []string{
		"request_id: " + poolTestCanonicalRequestID,
		"upstream_request_id: " + poolTestCPAUpstreamID,
		"newapi_request_id: " + poolTestCanonicalRequestID,
		"newapi_upstream_request_id: \n",
	} {
		if !strings.Contains(poolRequestLogBody(entry), fragment) {
			t.Fatalf("fallback download body is missing %q", fragment)
		}
	}
}

func TestPoolLogPayloadOmitsAllRequestIdentifiersForLifecycleEntry(t *testing.T) {
	payload := poolLogEntriesPayload([]poolLogEntry{{
		Timestamp: poolTestNow.Unix(),
		Level:     "INFO",
		Message:   "credential added",
		Source:    "cpa",
	}})[0]
	for _, field := range []string{
		"request_id",
		"upstream_request_id",
		"cpa_request_id",
		"cpa_upstream_request_id",
	} {
		if value, exists := payload[field]; exists {
			t.Fatalf("lifecycle payload unexpectedly contains %q=%#v", field, value)
		}
	}
}
