package management

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
)

func TestPoolAuthFilesContainOnlyClaudeAccounts(t *testing.T) {
	files := poolAuthFiles(time.Date(2026, time.August, 15, 12, 0, 0, 0, time.UTC))
	if len(files) != 300 {
		t.Fatalf("auth file count = %d, want 300", len(files))
	}

	emails := make(map[string]bool, len(files))
	statuses := make(map[string]bool)
	encoded, errMarshal := json.Marshal(files)
	if errMarshal != nil {
		t.Fatalf("marshal auth files: %v", errMarshal)
	}
	lower := strings.ToLower(string(encoded))
	for _, forbidden := range []string{"access_token", "refresh_token", "gemini", "codex", "antigravity", "demo"} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("auth payload contains forbidden value %q", forbidden)
		}
	}
	for _, file := range files {
		if got := file["provider"]; got != "claude" {
			t.Fatalf("provider = %q, want claude", got)
		}
		email := file["email"].(string)
		if !strings.HasSuffix(email, "@example.net") && !strings.HasSuffix(email, "@example.org") {
			t.Fatalf("email does not use a reserved domain: %q", email)
		}
		if emails[email] {
			t.Fatalf("duplicate email: %q", email)
		}
		emails[email] = true
		statuses[file["status"].(string)] = true
	}
	for _, status := range []string{"active", "error", "disabled"} {
		if !statuses[status] {
			t.Fatalf("auth payload is missing %q status", status)
		}
	}
}

func TestPoolLogsRespectCutoffAndLimit(t *testing.T) {
	now := time.Date(2026, time.August, 15, 12, 0, 17, 0, time.UTC)
	lines, total, latest := poolLogLines(now, now.Add(-10*time.Minute).Unix(), 5)
	if total == 0 {
		t.Fatal("expected logs after cutoff")
	}
	if len(lines) != 5 {
		t.Fatalf("log count = %d, want 5", len(lines))
	}
	if latest != now.Truncate(30*time.Second).Unix() {
		t.Fatalf("latest timestamp = %d", latest)
	}
	joined := strings.ToLower(strings.Join(lines, "\n"))
	if !strings.Contains(joined, "provider=claude") || strings.Contains(joined, "demo") {
		t.Fatalf("unexpected log content: %s", joined)
	}
}

func TestPoolUsageChangesWithTime(t *testing.T) {
	now := time.Date(2026, time.August, 15, 12, 0, 0, 0, time.UTC)
	first := poolUsage(now, 42)["five_hour"].(gin.H)
	second := poolUsage(now.Add(10*time.Minute), 42)["five_hour"].(gin.H)
	if second["utilization"].(float64) <= first["utilization"].(float64) {
		t.Fatal("five-hour utilization should increase as requests accumulate")
	}
	if first["resets_at"] != second["resets_at"] {
		t.Fatal("reset time should remain stable within the same window")
	}
}

func TestPoolAPICallReturnsClaudeUsageAndBlocksOtherTargets(t *testing.T) {
	gin.SetMode(gin.TestMode)
	authIndex := "claude-oauth-0042"
	request := apiCallRequest{AuthIndexSnake: &authIndex, Method: http.MethodGet, URL: "https://api.anthropic.com/api/oauth/usage"}
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	poolAPICall(ctx, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "five_hour") {
		t.Fatalf("usage response = %d %s", recorder.Code, recorder.Body.String())
	}

	request.URL = "https://example.com/"
	recorder = httptest.NewRecorder()
	ctx, _ = gin.CreateTestContext(recorder)
	poolAPICall(ctx, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("unsupported target status = %d, want %d", recorder.Code, http.StatusForbidden)
	}
}

func TestPoolModeListAuthFilesUsesPoolData(t *testing.T) {
	t.Setenv(poolModeEnvironment, "true")
	gin.SetMode(gin.TestMode)

	h := NewHandlerWithoutConfigFilePath(&config.Config{}, nil)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/v0/management/auth-files", nil)

	h.ListAuthFiles(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}
	var payload struct {
		Files []map[string]any `json:"files"`
	}
	if errDecode := json.Unmarshal(recorder.Body.Bytes(), &payload); errDecode != nil {
		t.Fatalf("decode auth payload: %v", errDecode)
	}
	if len(payload.Files) != 300 {
		t.Fatalf("auth file count = %d, want 300", len(payload.Files))
	}
}

func TestPoolRequestPolicyIsReadOnly(t *testing.T) {
	if !poolRequestAllowed(http.MethodGet, "/v0/management/auth-files") {
		t.Fatal("auth list should be available")
	}
	if !poolRequestAllowed(http.MethodPost, "/v0/management/api-call") {
		t.Fatal("quota API call should be available")
	}
	if poolRequestAllowed(http.MethodDelete, "/v0/management/auth-files") {
		t.Fatal("delete should be blocked")
	}
	if poolRequestAllowed(http.MethodGet, "/v0/management/anthropic-auth-url") {
		t.Fatal("OAuth initiation should be blocked")
	}
	if poolRequestAllowed(http.MethodGet, "/v0/management/auth-files/download") {
		t.Fatal("credential download should be blocked")
	}
}
