package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readDeploymentAsset(t *testing.T, parts ...string) string {
	t.Helper()
	path := filepath.Join(append([]string{"..", "..", "pool", "log-bridge"}, parts...)...)
	content, errRead := os.ReadFile(path)
	if errRead != nil {
		t.Fatalf("read %s: %v", path, errRead)
	}
	return string(content)
}

func TestDeploymentAssetsKeepBridgeIsolated(t *testing.T) {
	dockerignore := readDeploymentAsset(t, ".dockerignore")
	for _, required := range []string{"secrets", "secrets/**", ".env", ".env.*"} {
		if !strings.Contains(dockerignore, required) {
			t.Fatalf("bridge .dockerignore is missing %q", required)
		}
	}

	compose := readDeploymentAsset(t, "docker-compose.yml")
	for _, required := range []string{
		"context: .",
		"read_only: true",
		"user: \"65532:65532\"",
		"CPA_LOG_BRIDGE_DATABASE_URL_FILE:",
		"CPA_LOG_BRIDGE_BEARER_TOKEN_FILE:",
		"name: new-api-stack_app",
	} {
		if !strings.Contains(compose, required) {
			t.Fatalf("compose is missing %q", required)
		}
	}
	for _, forbidden := range []string{"ports:", "CPA_LOG_BRIDGE_DATABASE_URL:", "CPA_LOG_BRIDGE_BEARER_TOKEN:"} {
		if strings.Contains(compose, forbidden) {
			t.Fatalf("compose contains forbidden setting %q", forbidden)
		}
	}

	caddy := readDeploymentAsset(t, "Caddyfile.snippet")
	for _, required := range []string{
		"path /internal/cpa-pool/logs /internal/cpa-pool/logs/*",
		"remote_ip 43.156.101.97/32",
		"uri strip_prefix /internal/cpa-pool/logs",
		"respond 404",
	} {
		if !strings.Contains(caddy, required) {
			t.Fatalf("Caddy snippet is missing %q", required)
		}
	}
}

func TestSQLAssetsExposeOnlyFixedReadOnlyFunctions(t *testing.T) {
	view := readDeploymentAsset(t, "sql", "001_view.sql")
	projectionStart := strings.Index(view, "SELECT\n")
	projectionEnd := strings.Index(view, "\nFROM public.logs")
	if projectionStart < 0 || projectionEnd <= projectionStart {
		t.Fatal("could not locate view projection")
	}
	projection := view[projectionStart:projectionEnd]
	for _, forbidden := range []string{"username", "token_name", "user_id", "channel_id", "prompt_tokens", "completion_tokens", "quota", "logs.ip", "logs.content", `logs."group"`} {
		if strings.Contains(projection, forbidden) {
			t.Fatalf("view projection contains forbidden field %q", forbidden)
		}
	}
	if !strings.Contains(view, "9223372036854775") {
		t.Fatal("latency conversion is missing its int64-only overflow guard")
	}
	for _, required := range []string{
		"logs.model_name AS model_name",
		"OCTET_LENGTH(logs.model_name) BETWEEN 8 AND 128",
		"OCTET_LENGTH(logs.request_id) BETWEEN 1 AND 128",
		"OCTET_LENGTH(logs.upstream_request_id) BETWEEN 1 AND 128",
		"!~ '[[:cntrl:]]'",
		"ELSE NULL",
	} {
		if !strings.Contains(view, required) {
			t.Fatalf("view is missing safe opaque-field condition %q", required)
		}
	}
	for _, forbidden := range []string{
		"LEFT(COALESCE(logs.model_name",
		"LENGTH(logs.request_id) BETWEEN 1 AND 64",
	} {
		if strings.Contains(view, forbidden) {
			t.Fatalf("view contains obsolete truncation rule %q", forbidden)
		}
	}
	if !strings.Contains(view, "WITH (security_barrier = true)") {
		t.Fatal("the defensive view must retain its security barrier")
	}
	if strings.Contains(view, "RESET (security_barrier)") {
		t.Fatal("security_barrier must never be reset")
	}
	if strings.Count(view, `logs."group" = 'max'`) != 7 {
		t.Fatal("the view and every reader-callable query must filter the New API max group")
	}
	for _, functionName := range []string{
		"changes", "search_initial", "search_boundary", "search_before", "lookup_primary", "lookup_upstream",
	} {
		if !strings.Contains(view, "FUNCTION cpa_log_bridge."+functionName+"(") {
			t.Fatalf("fixed bridge function %q is missing", functionName)
		}
	}
	if strings.Count(view, "SECURITY DEFINER") != 6 ||
		strings.Count(view, "SET search_path = pg_catalog") != 6 ||
		strings.Count(view, "SET row_security = on") != 6 {
		t.Fatal("every reader-callable function must be SECURITY DEFINER with fixed search_path and row_security")
	}
	if strings.Count(view, "PARALLEL UNSAFE") != 7 {
		t.Fatal("safe-status and every reader-callable function must be explicitly PARALLEL UNSAFE")
	}
	if strings.Count(view, "source_id bigint, created_at bigint, type integer, model_name text,") != 5 ||
		strings.Count(view, "status integer, latency_ms bigint, request_id text, upstream_request_id text") != 5 ||
		!strings.Contains(view, "RETURNS TABLE (created_at bigint, source_id bigint)") {
		t.Fatal("reader-callable functions must keep their fixed narrow return schemas")
	}
	if strings.Count(view, "1001)") < 3 || !strings.Contains(view, "LIMIT 100") || !strings.Contains(view, "LIMIT 1") {
		t.Fatal("fixed bridge functions are missing hard server-side row limits")
	}

	role := readDeploymentAsset(t, "sql", "002_reader_role.sql")
	if !strings.Contains(role, "REVOKE ALL ON cpa_log_bridge.claude_logs FROM cpa_log_reader") {
		t.Fatal("reader role must have any legacy view grant removed")
	}
	for _, forbidden := range []string{
		"GRANT SELECT ON public.",
		"GRANT SELECT ON cpa_log_bridge.claude_logs",
		"GRANT EXECUTE ON FUNCTION cpa_log_bridge.safe_status_code",
	} {
		if strings.Contains(role, forbidden) {
			t.Fatalf("reader role contains forbidden grant %q", forbidden)
		}
	}
	for _, required := range []string{
		"CREATE ROLE cpa_log_bridge_owner NOLOGIN",
		"WITH NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS",
		"GRANT SELECT (",
		") ON public.logs TO cpa_log_bridge_owner",
		"ALTER VIEW cpa_log_bridge.claude_logs OWNER TO cpa_log_bridge_owner",
		"ALTER SCHEMA cpa_log_bridge OWNER TO cpa_log_bridge_owner",
	} {
		if !strings.Contains(view, required) {
			t.Fatalf("dedicated function owner setup is missing %q", required)
		}
	}
	grantStart := strings.Index(view, "GRANT SELECT (")
	if grantStart < 0 {
		t.Fatal("could not locate owner column grant")
	}
	grantEnd := strings.Index(view[grantStart:], ") ON public.logs TO cpa_log_bridge_owner")
	if grantEnd < 0 {
		t.Fatal("could not locate end of owner column grant")
	}
	for _, forbiddenColumn := range []string{"username", "user_id", "token_id", "token_name", "channel_id", "ip", "content", "quota"} {
		if strings.Contains(view[grantStart:grantStart+grantEnd], forbiddenColumn) {
			t.Fatalf("function owner grant includes forbidden column %q", forbiddenColumn)
		}
	}
	if !strings.Contains(view[grantStart:grantStart+grantEnd], `"group"`) {
		t.Fatal("function owner grant must include only the group column needed for max filtering")
	}
	if strings.Count(role, "'group'") != 2 {
		t.Fatal("owner privilege verification must allow the group filter column and no other additions")
	}
	for _, rangeGuard := range []string{
		"p_from >= 0",
		"p_to >= p_from",
		"p_to - p_from <= 7776000",
		"p_to <= EXTRACT(EPOCH FROM CURRENT_TIMESTAMP)::bigint + 60",
	} {
		if strings.Count(view, rangeGuard) != 2 {
			t.Fatalf("both search functions must enforce range guard %q", rangeGuard)
		}
	}
	for _, required := range []string{
		"REVOKE cpa_log_bridge_owner FROM cpa_log_reader",
		"has_any_column_privilege('cpa_log_reader', 'public.logs', 'SELECT')",
		"has_schema_privilege('cpa_log_reader', 'cpa_log_bridge', 'CREATE')",
		"pg_has_role('cpa_log_reader', 'cpa_log_bridge_owner', 'MEMBER')",
		"privilege.grantee = 0",
	} {
		if !strings.Contains(role, required) {
			t.Fatalf("reader/owner negative verification is missing %q", required)
		}
	}
	for _, signature := range []string{
		"changes(bigint, integer)",
		"search_initial(bigint, bigint, integer)",
		"search_boundary(bigint)",
		"search_before(bigint, bigint, bigint, bigint, integer)",
		"lookup_primary(text)",
		"lookup_upstream(text)",
	} {
		if !strings.Contains(role, "GRANT EXECUTE ON FUNCTION cpa_log_bridge."+signature+" TO cpa_log_reader") {
			t.Fatalf("reader role is missing EXECUTE on %q", signature)
		}
	}

	searchIndex := readDeploymentAsset(t, "sql", "003_search_index.sql")
	for _, required := range []string{
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_cpa_log_bridge_max_created_id_v3",
		"ON public.logs (created_at DESC, id DESC)",
		"WHERE type IN (2, 5)",
		"AND created_at >= 0",
		`AND "group" = 'max'`,
		"AND model_name LIKE 'claude-%'",
		"AND OCTET_LENGTH(model_name) BETWEEN 8 AND 128",
		"AND model_name !~ '[[:cntrl:]]'",
		"AND request_id IS NOT NULL",
		"AND OCTET_LENGTH(request_id) BETWEEN 1 AND 128",
		"AND request_id !~ '[[:cntrl:]]'",
	} {
		if !strings.Contains(searchIndex, required) {
			t.Fatalf("search index is missing %q", required)
		}
	}
	for _, viewPredicate := range []string{
		"logs.type IN (2, 5)",
		"logs.created_at >= 0",
		`logs."group" = 'max'`,
		"logs.model_name LIKE 'claude-%'",
		"OCTET_LENGTH(logs.model_name) BETWEEN 8 AND 128",
		"logs.model_name !~ '[[:cntrl:]]'",
		"logs.request_id IS NOT NULL",
		"OCTET_LENGTH(logs.request_id) BETWEEN 1 AND 128",
		"logs.request_id !~ '[[:cntrl:]]'",
	} {
		indexPredicate := strings.ReplaceAll(viewPredicate, "logs.", "")
		if !strings.Contains(searchIndex, indexPredicate) {
			t.Fatalf("search index predicate does not mirror view condition %q", viewPredicate)
		}
	}
}
