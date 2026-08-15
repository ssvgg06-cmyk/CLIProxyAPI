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

func TestDemoAuthFilesAreSyntheticAndVaried(t *testing.T) {
	files := demoAuthFiles(time.Date(2026, time.August, 15, 12, 0, 0, 0, time.UTC))
	if len(files) != 36 {
		t.Fatalf("demo auth file count = %d, want 36", len(files))
	}

	providers := make(map[string]bool)
	statuses := make(map[string]bool)
	encoded, errMarshal := json.Marshal(files)
	if errMarshal != nil {
		t.Fatalf("marshal demo auth files: %v", errMarshal)
	}
	if strings.Contains(string(encoded), "access_token") || strings.Contains(string(encoded), "refresh_token") {
		t.Fatal("demo auth payload must not contain token fields")
	}
	for _, file := range files {
		providers[file["provider"].(string)] = true
		statuses[file["status"].(string)] = true
		if !strings.HasSuffix(file["email"].(string), "@sample.test") {
			t.Fatalf("demo email is not reserved test data: %q", file["email"])
		}
	}
	if len(providers) != 4 {
		t.Fatalf("demo provider count = %d, want 4", len(providers))
	}
	for _, status := range []string{"active", "refreshing", "error", "disabled"} {
		if !statuses[status] {
			t.Fatalf("demo auth payload is missing %q status", status)
		}
	}
}

func TestDemoLogsRespectCutoffAndLimit(t *testing.T) {
	now := time.Date(2026, time.August, 15, 12, 0, 0, 0, time.Local)
	lines, total, latest := demoLogLines(now, now.Add(-10*time.Minute).Unix(), 5)
	if total == 0 {
		t.Fatal("expected demo logs after cutoff")
	}
	if len(lines) != 5 {
		t.Fatalf("demo log count = %d, want 5", len(lines))
	}
	if latest != now.Unix() {
		t.Fatalf("latest timestamp = %d, want %d", latest, now.Unix())
	}
	if !strings.Contains(strings.Join(lines, "\n"), "request_id=demo-") {
		t.Fatal("demo logs should include synthetic request IDs")
	}
}

func TestDemoModeListAuthFilesUsesFixtures(t *testing.T) {
	t.Setenv(demoModeEnvironment, "true")
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
		t.Fatalf("decode demo auth payload: %v", errDecode)
	}
	if len(payload.Files) != 36 {
		t.Fatalf("demo auth file count = %d, want 36", len(payload.Files))
	}
}

func TestDemoRequestPolicyIsReadOnly(t *testing.T) {
	if !demoRequestAllowed(http.MethodGet, "/v0/management/auth-files") {
		t.Fatal("auth list should be available in demo mode")
	}
	if demoRequestAllowed(http.MethodDelete, "/v0/management/auth-files") {
		t.Fatal("delete should be blocked in demo mode")
	}
	if demoRequestAllowed(http.MethodGet, "/v0/management/codex-auth-url") {
		t.Fatal("OAuth initiation should be blocked in demo mode")
	}
	if demoRequestAllowed(http.MethodGet, "/v0/management/auth-files/download") {
		t.Fatal("credential download should be blocked in demo mode")
	}
}
