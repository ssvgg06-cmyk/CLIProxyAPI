package main

import (
	"strings"
	"testing"
)

func TestSafeStatusCode(t *testing.T) {
	tests := []struct {
		name       string
		logType    int
		statusCode int
		want       int
	}{
		{name: "valid success", logType: 2, statusCode: 201, want: 201},
		{name: "valid error", logType: 5, statusCode: 429, want: 429},
		{name: "success fallback", logType: 2, statusCode: 0, want: 200},
		{name: "error fallback", logType: 5, statusCode: 999, want: 502},
		{name: "unknown fallback", logType: 0, statusCode: -1, want: 502},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := safeStatusCode(test.logType, test.statusCode); got != test.want {
				t.Fatalf("safeStatusCode(%d, %d) = %d, want %d", test.logType, test.statusCode, got, test.want)
			}
		})
	}
}

func TestNormalizeRecordClampsUntrustedValues(t *testing.T) {
	record := LogRecord{Type: 5, Status: 700, LatencyMS: -4}
	normalizeRecord(&record)
	if record.Status != 502 {
		t.Fatalf("status = %d, want 502", record.Status)
	}
	if record.LatencyMS != 0 {
		t.Fatalf("latency_ms = %d, want 0", record.LatencyMS)
	}
}

func TestQueriesUseOnlyFixedParameterizedSecurityDefinerFunctions(t *testing.T) {
	queries := map[string]string{
		"changes":         changesSQL,
		"search":          searchSQL,
		"search cursor":   searchBeforeSQL,
		"lookup primary":  lookupPrimarySQL,
		"lookup upstream": lookupUpstreamSQL,
	}
	for name, query := range queries {
		t.Run(name, func(t *testing.T) {
			if !strings.Contains(query, "$1") {
				t.Fatal("query does not contain a positional parameter")
			}
			lower := strings.ToLower(query)
			for _, forbidden := range []string{
				"public.logs", "claude_logs", "username", "token_name", "user_id", " ip", "content", "other", "quota", "prompt_tokens", "completion_tokens", "channel_id",
			} {
				if strings.Contains(lower, forbidden) {
					t.Fatalf("query contains forbidden field %q", forbidden)
				}
			}
			if !strings.Contains(lower, "cpa_log_bridge.") {
				t.Fatal("query does not call a schema-qualified bridge function")
			}
		})
	}
	for functionName, query := range map[string]string{
		"changes":         changesSQL,
		"search_initial":  searchSQL,
		"search_boundary": searchBoundarySQL,
		"search_before":   searchBeforeSQL,
		"lookup_primary":  lookupPrimarySQL,
		"lookup_upstream": lookupUpstreamSQL,
	} {
		if !strings.Contains(query, "cpa_log_bridge."+functionName+"(") {
			t.Fatalf("query does not call fixed function %s", functionName)
		}
	}
	if strings.Contains(lookupPrimarySQL, "OR upstream_request_id") {
		t.Fatal("primary lookup must not mix upstream matches")
	}
	if !strings.Contains(searchSQL, "ORDER BY created_at DESC, source_id DESC") {
		t.Fatal("initial search must use the stable time and source-id order")
	}
	if !strings.Contains(searchBoundarySQL, "SELECT created_at, source_id") ||
		!strings.Contains(searchBoundarySQL, "cpa_log_bridge.search_boundary($1)") {
		t.Fatal("before_id must be resolved through the fixed boundary function")
	}
	if !strings.Contains(searchBeforeSQL, "cpa_log_bridge.search_before($1, $2, $3, $4, $5)") {
		t.Fatal("cursor search must pass the resolved composite boundary to the fixed function")
	}
	if !strings.Contains(searchBeforeSQL, "ORDER BY created_at DESC, source_id DESC") {
		t.Fatal("cursor search must preserve the stable composite order")
	}
	if !strings.Contains(lookupUpstreamSQL, "ORDER BY source_id DESC") || !strings.Contains(lookupUpstreamSQL, "LIMIT 100") {
		t.Fatal("upstream lookup must return at most 100 newest matches")
	}
}
