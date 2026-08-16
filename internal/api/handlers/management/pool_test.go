package management

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
)

func newTestPool(t *testing.T, now time.Time) *poolSimulator {
	t.Helper()
	return newPoolSimulator(filepath.Join(t.TempDir(), "pool-state.json"), now, 424242)
}

func TestPoolAuthFilesChangeCountWithinBounds(t *testing.T) {
	now := time.Date(2026, time.August, 16, 12, 0, 0, 0, time.UTC)
	pool := newTestPool(t, now)
	first := pool.authFiles(now, true)
	second := pool.authFiles(now.Add(time.Minute), true)
	for _, count := range []int{len(first), len(second)} {
		if count < poolMinimumAccounts || count > poolMaximumAccounts {
			t.Fatalf("auth file count = %d, want %d..%d", count, poolMinimumAccounts, poolMaximumAccounts)
		}
	}
	if len(first) == poolInitialAccounts {
		t.Fatal("first refresh should change the initial account count")
	}
	if len(first) == len(second) {
		t.Fatal("each refresh should change the account count")
	}

	firstIDs := make(map[string]bool, len(first))
	for _, file := range first {
		firstIDs[file["auth_index"].(string)] = true
	}
	overlap := 0
	for _, file := range second {
		if firstIDs[file["auth_index"].(string)] {
			overlap++
		}
	}
	if overlap < 240 {
		t.Fatalf("only %d accounts survived a refresh; identities should remain stable", overlap)
	}
}

func TestPoolAuthFilesUseUniqueMaskedGmailOnly(t *testing.T) {
	now := time.Date(2026, time.August, 16, 12, 0, 0, 0, time.UTC)
	files := newTestPool(t, now).authFiles(now, false)
	pattern := regexp.MustCompile(`^[a-z]{2}\*{4,8}\d{4}@gmail\.com$`)
	emails := make(map[string]bool, len(files))
	statuses := make(map[string]bool)
	for _, file := range files {
		email := file["email"].(string)
		if !pattern.MatchString(email) {
			t.Fatalf("email is not masked Gmail: %q", email)
		}
		if emails[email] {
			t.Fatalf("duplicate masked Gmail: %q", email)
		}
		emails[email] = true
		if !strings.Contains(file["name"].(string), email) {
			t.Fatalf("credential name does not use masked Gmail: %q", file["name"])
		}
		if got := file["provider"]; got != "claude" {
			t.Fatalf("provider = %q, want claude", got)
		}
		if got := file["account_type"]; got != "Claude Max" {
			t.Fatalf("account type = %q, want Claude Max", got)
		}
		statuses[file["status"].(string)] = true
	}
	if !statuses["error"] || !statuses["disabled"] {
		t.Fatalf("initial pool should include error and disabled accounts: %#v", statuses)
	}
	encoded, errMarshal := json.Marshal(files)
	if errMarshal != nil {
		t.Fatalf("marshal auth files: %v", errMarshal)
	}
	lower := strings.ToLower(string(encoded))
	for _, forbidden := range []string{"access_token", "refresh_token", "example.net", "example.org", "gemini", "codex", "antigravity"} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("auth payload contains forbidden value %q", forbidden)
		}
	}
}

func TestPoolReloadMigratesEveryPlanToMax(t *testing.T) {
	now := time.Date(2026, time.August, 16, 12, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "pool-state.json")
	first := newPoolSimulator(path, now, 1234)
	first.mu.Lock()
	first.state.Accounts[0].Plan = "Claude Pro"
	first.state.Accounts[1].Plan = "Claude Team"
	first.state.Logs = append(first.state.Logs, poolLogEntry{Timestamp: now.UnixMilli(), Line: "plan=Claude Pro plan=Claude Team"})
	if err := first.persistLocked(); err != nil {
		first.mu.Unlock()
		t.Fatalf("persist legacy plans: %v", err)
	}
	first.mu.Unlock()

	reloaded := newPoolSimulator(path, now.Add(time.Minute), 9999)
	files := reloaded.authFiles(now.Add(time.Minute), false)
	for _, file := range files {
		if got := file["account_type"]; got != "Claude Max" {
			t.Fatalf("migrated account type = %q, want Claude Max", got)
		}
	}
	reloaded.mu.Lock()
	defer reloaded.mu.Unlock()
	for _, entry := range reloaded.state.Logs {
		if strings.Contains(entry.Line, "Claude Pro") || strings.Contains(entry.Line, "Claude Team") {
			t.Fatalf("legacy plan remains in log: %q", entry.Line)
		}
	}
}

func TestPoolUsageDeclinesAndQuotaQueryDoesNotAdvancePool(t *testing.T) {
	now := time.Date(2026, time.August, 16, 12, 0, 0, 0, time.UTC)
	pool := newTestPool(t, now)
	pool.mu.Lock()
	account := pool.state.Accounts[0]
	account.FiveHour.Utilization = 2
	account.SevenDay.Utilization = 2
	account.FiveHour.RatePerMinute = 0.02
	account.SevenDay.RatePerMinute = 0.02
	authIndex := account.AuthIndex
	revision := pool.state.Revision
	pool.mu.Unlock()

	first, ok := pool.usage(now, authIndex)
	if !ok {
		t.Fatal("usage should be available")
	}
	second, ok := pool.usage(now.Add(10*time.Minute), authIndex)
	if !ok {
		t.Fatal("later usage should be available")
	}
	firstUsed := first["five_hour"].(gin.H)["utilization"].(float64)
	secondUsed := second["five_hour"].(gin.H)["utilization"].(float64)
	if secondUsed <= firstUsed {
		t.Fatalf("utilization did not increase: %f -> %f", firstUsed, secondUsed)
	}
	pool.mu.Lock()
	defer pool.mu.Unlock()
	if pool.state.Revision != revision {
		t.Fatal("quota queries must not advance the pool revision")
	}
}

func TestExhaustedAccountIsReplacedAndReadableDuringGracePeriod(t *testing.T) {
	now := time.Date(2026, time.August, 16, 12, 0, 0, 0, time.UTC)
	pool := newTestPool(t, now)
	pool.mu.Lock()
	account := pool.state.Accounts[0]
	oldAuthIndex := account.AuthIndex
	oldEmail := account.Email
	account.FiveHour.Utilization = 100
	account.Status = "error"
	account.StatusMessage = "Quota exhausted"
	account.Unavailable = true
	account.ExhaustedRefreshes = 1
	account.RetireAfter = 1
	pool.mu.Unlock()

	files := pool.authFiles(now.Add(time.Minute), true)
	for _, file := range files {
		if file["auth_index"] == oldAuthIndex {
			t.Fatal("exhausted account should leave the active list")
		}
	}
	if _, ok := pool.usage(now.Add(2*time.Minute), oldAuthIndex); !ok {
		t.Fatal("retired account should remain queryable during the grace period")
	}
	newEmailFound := false
	for _, file := range files {
		if file["email"] != oldEmail && file["created_at"].(time.Time).After(now.Add(-10*time.Minute)) {
			newEmailFound = true
			break
		}
	}
	if !newEmailFound {
		t.Fatal("expected a newly registered credential with a different Gmail")
	}
	pool.authFiles(now.Add(poolRetiredGracePeriod+2*time.Minute), true)
	if _, ok := pool.usage(now.Add(poolRetiredGracePeriod+3*time.Minute), oldAuthIndex); ok {
		t.Fatal("retired account should expire after the grace period")
	}
}

func TestPoolStatePersistsAndReloads(t *testing.T) {
	now := time.Date(2026, time.August, 16, 12, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "pool-state.json")
	first := newPoolSimulator(path, now, 1234)
	files := first.authFiles(now, true)
	first.mu.Lock()
	revision := first.state.Revision
	seed := first.state.Seed
	first.mu.Unlock()

	second := newPoolSimulator(path, now.Add(time.Hour), 9999)
	reloaded := second.authFiles(now.Add(time.Hour), false)
	second.mu.Lock()
	defer second.mu.Unlock()
	if second.state.Revision != revision || second.state.Seed != seed {
		t.Fatal("reloaded state did not preserve revision and seed")
	}
	if len(reloaded) != len(files) {
		t.Fatalf("reloaded account count = %d, want %d", len(reloaded), len(files))
	}
	if reloaded[0]["auth_index"] != files[0]["auth_index"] {
		t.Fatal("reloaded account identity changed")
	}
}

func TestCorruptPoolStateRebuildsSafely(t *testing.T) {
	now := time.Date(2026, time.August, 16, 12, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "pool-state.json")
	if errWrite := os.WriteFile(path, []byte("{broken"), 0o600); errWrite != nil {
		t.Fatalf("write corrupt state: %v", errWrite)
	}
	pool := newPoolSimulator(path, now, 1234)
	files := pool.authFiles(now, false)
	if len(files) != poolInitialAccounts {
		t.Fatalf("rebuilt account count = %d, want %d", len(files), poolInitialAccounts)
	}
}

func TestPoolLogsAdvanceAndUseCurrentModels(t *testing.T) {
	now := time.Date(2026, time.August, 16, 12, 0, 0, 0, time.UTC)
	pool := newTestPool(t, now)
	_, _, latest := pool.logLines(now, 0, 5)
	lines, total, nextLatest := pool.logLines(now.Add(31*time.Second), latest, 10)
	if total == 0 || len(lines) == 0 || nextLatest <= latest {
		t.Fatal("expected a new rolling log entry")
	}
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "provider=claude") {
		t.Fatalf("unexpected logs: %s", joined)
	}
	foundModel := false
	for _, model := range poolModelIDs {
		if strings.Contains(joined, model) {
			foundModel = true
		}
	}
	if !foundModel {
		t.Fatalf("logs do not use current models: %s", joined)
	}
	for _, oldModel := range []string{"claude-opus-4-6", "claude-sonnet-4-6", "claude-haiku-4-5 ", "@example"} {
		if strings.Contains(joined, oldModel) {
			t.Fatalf("logs contain obsolete or unmasked value %q", oldModel)
		}
	}
}

func TestPoolModelsMatchOfficialSnapshot(t *testing.T) {
	models := poolModelsForAuth("anything")
	want := []string{"claude-fable-5", "claude-opus-4-8", "claude-sonnet-5", "claude-haiku-4-5-20251001"}
	if len(models) != len(want) {
		t.Fatalf("model count = %d, want %d", len(models), len(want))
	}
	for index := range want {
		if models[index]["id"] != want[index] {
			t.Fatalf("model %d = %q, want %q", index, models[index]["id"], want[index])
		}
	}
}

func TestPoolSimulatorConcurrentReadsAndRefreshes(t *testing.T) {
	now := time.Date(2026, time.August, 16, 12, 0, 0, 0, time.UTC)
	pool := newTestPool(t, now)
	authIndex := pool.authFiles(now, false)[0]["auth_index"].(string)
	var wait sync.WaitGroup
	for i := 0; i < 24; i++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			at := now.Add(time.Duration(index) * time.Second)
			switch index % 3 {
			case 0:
				pool.authFiles(at, index%6 == 0)
			case 1:
				pool.usage(at, authIndex)
			case 2:
				pool.logLines(at, 0, 5)
			}
		}(i)
	}
	wait.Wait()
	count := len(pool.authFiles(now.Add(time.Minute), false))
	if count < poolMinimumAccounts || count > poolMaximumAccounts {
		t.Fatalf("concurrent account count = %d", count)
	}
}

func TestPoolAPICallReturnsUsageAndBlocksOtherTargets(t *testing.T) {
	gin.SetMode(gin.TestMode)
	now := time.Date(2026, time.August, 16, 12, 0, 0, 0, time.UTC)
	pool := newTestPool(t, now)
	handler := &Handler{poolMode: true, poolState: pool}
	authIndex := pool.authFiles(now, false)[0]["auth_index"].(string)
	request := apiCallRequest{AuthIndexSnake: &authIndex, Method: http.MethodGet, URL: "https://api.anthropic.com/api/oauth/usage"}
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	handler.poolAPICall(ctx, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "five_hour") {
		t.Fatalf("usage response = %d %s", recorder.Code, recorder.Body.String())
	}

	request.URL = "https://example.com/"
	recorder = httptest.NewRecorder()
	ctx, _ = gin.CreateTestContext(recorder)
	handler.poolAPICall(ctx, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("unsupported target status = %d, want %d", recorder.Code, http.StatusForbidden)
	}
}

func TestPoolModeListAuthFilesUsesPersistentPool(t *testing.T) {
	t.Setenv(poolModeEnvironment, "true")
	t.Setenv(poolStateEnvironment, filepath.Join(t.TempDir(), "pool-state.json"))
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
	if len(payload.Files) < poolMinimumAccounts || len(payload.Files) > poolMaximumAccounts || len(payload.Files) == poolInitialAccounts {
		t.Fatalf("dynamic auth file count = %d", len(payload.Files))
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
