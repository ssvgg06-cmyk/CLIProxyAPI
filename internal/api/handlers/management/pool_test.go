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

var poolTestNow = time.Date(2026, time.August, 16, 12, 0, 0, 0, time.UTC)

func newTestPool(t *testing.T, now time.Time) *poolSimulator {
	t.Helper()
	return newPoolSimulator(filepath.Join(t.TempDir(), "pool-state.json"), now, 424242)
}

func poolTestFilter(from, to time.Time, limit int) poolLogFilter {
	return poolLogFilter{From: from, To: to, Limit: limit}
}

func TestPoolAuthFilesStayWithinBounds(t *testing.T) {
	pool := newTestPool(t, poolTestNow)
	first := pool.authFiles(poolTestNow, true)
	second := pool.authFiles(poolTestNow.Add(24*time.Hour), true)
	for _, count := range []int{len(first), len(second)} {
		if count < poolMinimumAccounts || count > poolMaximumAccounts {
			t.Fatalf("auth file count = %d, outside expected bounds", count)
		}
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
		t.Fatalf("only %d accounts survived a day; identities should remain stable", overlap)
	}
}

// The pool must evolve on wall-clock epochs, never on request volume, otherwise
// historical windows could not be reproduced.
func TestPoolEvolutionIsEpochDrivenNotRequestDriven(t *testing.T) {
	pool := newTestPool(t, poolTestNow)
	baseline := pool.authFiles(poolTestNow, true)
	pool.mu.Lock()
	revision := pool.state.Revision
	epoch := pool.state.LastEpoch
	pool.mu.Unlock()

	for i := 0; i < 50; i++ {
		if got := len(pool.authFiles(poolTestNow.Add(time.Duration(i)*time.Second), true)); got != len(baseline) {
			t.Fatalf("account count changed within one epoch: %d -> %d", len(baseline), got)
		}
	}

	pool.mu.Lock()
	defer pool.mu.Unlock()
	if pool.state.Revision != revision {
		t.Fatalf("revision advanced within one epoch: %d -> %d", revision, pool.state.Revision)
	}
	if pool.state.LastEpoch != epoch {
		t.Fatalf("epoch advanced without wall-clock progress: %d -> %d", epoch, pool.state.LastEpoch)
	}
}

func TestPoolAuthFilesUseUniqueMaskedGmailOnly(t *testing.T) {
	files := newTestPool(t, poolTestNow).authFiles(poolTestNow, false)
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
	path := filepath.Join(t.TempDir(), "pool-state.json")
	first := newPoolSimulator(path, poolTestNow, 1234)
	first.mu.Lock()
	first.state.Accounts[0].Plan = "Claude Pro"
	first.state.Accounts[1].Plan = "Claude Team"
	if err := first.persistLocked(); err != nil {
		first.mu.Unlock()
		t.Fatalf("persist legacy plans: %v", err)
	}
	first.mu.Unlock()

	reloaded := newPoolSimulator(path, poolTestNow.Add(time.Minute), 9999)
	for _, file := range reloaded.authFiles(poolTestNow.Add(time.Minute), false) {
		if got := file["account_type"]; got != "Claude Max" {
			t.Fatalf("migrated account type = %q, want Claude Max", got)
		}
	}
}

// A v1 state file must upgrade in place without losing credential identity.
func TestPoolMigratesLegacyStateVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pool-state.json")
	legacy := map[string]any{
		"version":      1,
		"seed":         777,
		"revision":     12,
		"next_account": 2,
		"accounts": []map[string]any{{
			"id":         1,
			"auth_index": "claude-oauth-abc123",
			"email":      "al****1234@gmail.com",
			"name":       "claude-al****1234@gmail.com.json",
			"plan":       "Claude Max",
			"status":     "active",
			"created_at": poolTestNow.Add(-time.Hour),
			"updated_at": poolTestNow,
		}},
	}
	encoded, errEncode := json.Marshal(legacy)
	if errEncode != nil {
		t.Fatalf("encode legacy state: %v", errEncode)
	}
	if errWrite := os.WriteFile(path, encoded, 0o600); errWrite != nil {
		t.Fatalf("write legacy state: %v", errWrite)
	}

	pool := newPoolSimulator(path, poolTestNow, 1234)
	pool.mu.Lock()
	defer pool.mu.Unlock()
	if pool.state.Version != poolStateVersion {
		t.Fatalf("state version = %d, want %d", pool.state.Version, poolStateVersion)
	}
	if pool.state.Seed != 777 {
		t.Fatalf("seed = %d, want the preserved 777", pool.state.Seed)
	}
	if len(pool.state.Accounts) != poolMinimumAccounts || pool.state.Accounts[0].AuthIndex != "claude-oauth-abc123" {
		t.Fatal("migration did not preserve the existing credential identity")
	}
	if pool.state.Accounts[0].FirstSeen.IsZero() {
		t.Fatal("migration must backfill the roster entry date")
	}
}

func TestPoolUsageDeclinesAndQuotaQueryDoesNotAdvancePool(t *testing.T) {
	pool := newTestPool(t, poolTestNow)
	pool.mu.Lock()
	account := pool.state.Accounts[0]
	account.FiveHour.Utilization = 2
	account.SevenDay.Utilization = 2
	account.FiveHour.RatePerMinute = 0.02
	account.SevenDay.RatePerMinute = 0.02
	authIndex := account.AuthIndex
	revision := pool.state.Revision
	pool.mu.Unlock()

	first, ok := pool.usage(poolTestNow, authIndex)
	if !ok {
		t.Fatal("usage should be available")
	}
	second, ok := pool.usage(poolTestNow.Add(10*time.Minute), authIndex)
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

// Quota exhaustion is temporary: the credential must recover on window reset
// and stay resolvable throughout, so log lines never dangle.
func TestExhaustedAccountRecoversAndStaysResolvable(t *testing.T) {
	pool := newTestPool(t, poolTestNow)
	pool.mu.Lock()
	account := pool.state.Accounts[0]
	authIndex := account.AuthIndex
	account.FiveHour.Utilization = 100
	account.FiveHour.ResetAt = poolTestNow.Add(10 * time.Minute)
	pool.mu.Unlock()

	pool.authFiles(poolTestNow.Add(6*time.Minute), true)
	pool.mu.Lock()
	exhausted := pool.findAccountLocked(authIndex)
	message := exhausted.StatusMessage
	pool.mu.Unlock()
	if message != "Quota exhausted" {
		t.Fatalf("status message = %q, want Quota exhausted", message)
	}

	pool.authFiles(poolTestNow.Add(30*time.Minute), true)
	pool.mu.Lock()
	recovered := pool.findAccountLocked(authIndex)
	status := recovered.Status
	pool.mu.Unlock()
	if status != "active" {
		t.Fatalf("status = %q, want the credential to recover after the window reset", status)
	}
	if _, ok := pool.usage(poolTestNow.Add(31*time.Minute), authIndex); !ok {
		t.Fatal("credential must remain queryable")
	}
}

func TestPoolStatePersistsAndReloads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pool-state.json")
	first := newPoolSimulator(path, poolTestNow, 1234)
	files := first.authFiles(poolTestNow, true)
	first.mu.Lock()
	revision := first.state.Revision
	seed := first.state.Seed
	first.mu.Unlock()

	second := newPoolSimulator(path, poolTestNow, 9999)
	reloaded := second.authFiles(poolTestNow, false)
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
	path := filepath.Join(t.TempDir(), "pool-state.json")
	if errWrite := os.WriteFile(path, []byte("{broken"), 0o600); errWrite != nil {
		t.Fatalf("write corrupt state: %v", errWrite)
	}
	pool := newPoolSimulator(path, poolTestNow, 1234)
	if files := pool.authFiles(poolTestNow, false); len(files) != poolInitialAccounts {
		t.Fatalf("rebuilt account count = %d, want %d", len(files), poolInitialAccounts)
	}
}

func TestSemanticallyUnsafePoolStateRebuildsWithoutEmailLeak(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pool-state.json")
	first := newPoolSimulator(path, poolTestNow, 1234)
	first.mu.Lock()
	first.state.Accounts[0].Email = "complete.address@gmail.com"
	first.state.Accounts[0].Name = "claude-complete.address@gmail.com.json"
	if errPersist := first.persistLocked(); errPersist != nil {
		first.mu.Unlock()
		t.Fatalf("persist unsafe fixture: %v", errPersist)
	}
	first.mu.Unlock()

	rebuilt := newPoolSimulator(path, poolTestNow.Add(time.Minute), 9876)
	files := rebuilt.authFiles(poolTestNow.Add(time.Minute), false)
	if len(files) != poolInitialAccounts {
		t.Fatalf("rebuilt account count = %d, want %d", len(files), poolInitialAccounts)
	}
	encoded, errEncode := json.Marshal(files)
	if errEncode != nil {
		t.Fatal(errEncode)
	}
	if strings.Contains(string(encoded), "complete.address@gmail.com") {
		t.Fatal("unsafe full Gmail survived state validation")
	}
}

func TestPoolStateRepairsAccountBoundsWithoutReplacingIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pool-state.json")
	first := newPoolSimulator(path, poolTestNow, 2468)
	first.mu.Lock()
	wantSeed := first.state.Seed
	wantAuthIndex := first.state.Accounts[0].AuthIndex
	first.state.Accounts = first.state.Accounts[:1]
	if errPersist := first.persistLocked(); errPersist != nil {
		first.mu.Unlock()
		t.Fatalf("persist short pool fixture: %v", errPersist)
	}
	first.mu.Unlock()

	repaired := newPoolSimulator(path, poolTestNow.Add(time.Minute), 9999)
	repaired.mu.Lock()
	defer repaired.mu.Unlock()
	if repaired.state.Seed != wantSeed {
		t.Fatal("bounds repair replaced the persistent seed")
	}
	if len(repaired.state.Accounts) != poolMinimumAccounts {
		t.Fatalf("repaired account count = %d, want %d", len(repaired.state.Accounts), poolMinimumAccounts)
	}
	if repaired.state.Accounts[0].AuthIndex != wantAuthIndex {
		t.Fatal("bounds repair replaced an existing identity")
	}
}

// Rendered lines use the process wall clock, matching the proxy logger. Request
// identifiers are opaque New API values and are never parsed for a timestamp.
func TestPoolLineUsesLocalClockAndOpaqueRequestID(t *testing.T) {
	shanghai, errLoad := time.LoadLocation("Asia/Shanghai")
	if errLoad != nil {
		t.Skipf("timezone database unavailable: %v", errLoad)
	}
	previous := time.Local
	time.Local = shanghai
	defer func() { time.Local = previous }()

	entry := poolLogEntry{
		Timestamp: poolTestNow.Unix(),
		Level:     "INFO",
		Message:   "request completed",
		Source:    "newapi",
		RequestID: "legacy:id with opaque-format",
	}

	want := time.Unix(entry.Timestamp, 0).In(shanghai).Format("2006-01-02 15:04:05")
	if !strings.HasPrefix(entry.Line(), "["+want+"]") {
		t.Fatalf("line %q does not open with the local wall clock %q", entry.Line(), want)
	}
	utc := time.Unix(entry.Timestamp, 0).UTC().Format("2006-01-02 15:04:05")
	if want == utc {
		t.Fatal("test timezone must differ from UTC to be meaningful")
	}
	if strings.HasPrefix(entry.Line(), "["+utc+"]") {
		t.Fatal("line still renders UTC instead of the local wall clock")
	}

	if !strings.Contains(entry.Line(), `request_id="`+entry.RequestID+`"`) {
		t.Fatal("rendered line changed the opaque request identifier")
	}
}
func TestPoolModelMixMatchesFleetDistribution(t *testing.T) {
	models := poolModelsForAuth("anything")
	if len(models) != len(poolModelIDs) || len(models) != 4 {
		t.Fatalf("model count = %d, want 4", len(models))
	}
	seen := make(map[string]bool, len(models))
	for _, model := range models {
		id := model["id"].(string)
		if !strings.HasPrefix(id, "claude-") {
			t.Fatalf("unexpected model id %q", id)
		}
		if seen[id] {
			t.Fatalf("duplicate model id %q", id)
		}
		seen[id] = true
	}
	for _, required := range []string{"claude-fable-5", "claude-opus-4-8", "claude-sonnet-5", "claude-haiku-4-5-20251001"} {
		if !seen[required] {
			t.Fatalf("model mix is missing %q", required)
		}
	}
}

func TestPoolRecentRequestsUseBucketLabels(t *testing.T) {
	pool := newTestPool(t, poolTestNow)
	files := pool.authFiles(poolTestNow, false)
	buckets := files[0]["recent_requests"].([]gin.H)
	if len(buckets) != 20 {
		t.Fatalf("bucket count = %d, want 20", len(buckets))
	}
	pattern := regexp.MustCompile(`^\d{2}:\d{2}-\d{2}:\d{2}$`)
	for _, bucket := range buckets {
		label := bucket["time"].(string)
		if !pattern.MatchString(label) {
			t.Fatalf("bucket label %q does not use the HH:MM-HH:MM format", label)
		}
		if _, ok := bucket["success"].(int64); !ok {
			t.Fatalf("bucket success is not an integer: %#v", bucket["success"])
		}
	}
}

func TestPoolSimulatorConcurrentReadsAndRefreshes(t *testing.T) {
	pool := newTestPool(t, poolTestNow)
	authIndex := pool.authFiles(poolTestNow, false)[0]["auth_index"].(string)
	var wait sync.WaitGroup
	for i := 0; i < 24; i++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			at := poolTestNow.Add(time.Duration(index) * time.Second)
			switch index % 3 {
			case 0:
				pool.authFiles(at, index%6 == 0)
			case 1:
				pool.usage(at, authIndex)
			case 2:
				pool.mapRequestAccount(at, "opaque-request-id")
			}
		}(i)
	}
	wait.Wait()
	count := len(pool.authFiles(poolTestNow.Add(time.Minute), false))
	if count < poolMinimumAccounts {
		t.Fatalf("concurrent account count = %d", count)
	}
}

func TestPoolAPICallReturnsUsageAndBlocksOtherTargets(t *testing.T) {
	gin.SetMode(gin.TestMode)
	pool := newTestPool(t, poolTestNow)
	handler := &Handler{poolMode: true, poolState: pool}
	authIndex := pool.authFiles(poolTestNow, false)[0]["auth_index"].(string)
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
	if len(payload.Files) < poolMinimumAccounts {
		t.Fatalf("auth file count = %d, want at least %d", len(payload.Files), poolMinimumAccounts)
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
