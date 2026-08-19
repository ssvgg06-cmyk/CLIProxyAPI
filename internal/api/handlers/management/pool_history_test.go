package management

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var poolHistoryTestNow = time.Date(2026, time.August, 19, 12, 0, 0, 0, time.UTC)

func newPoolHistoryTestSimulator(t *testing.T, now time.Time) *poolSimulator {
	t.Helper()
	return newPoolSimulator(filepath.Join(t.TempDir(), "pool-state.json"), now, 919191)
}

func TestPoolFreshAccountFirstSeenMatchesJoinTime(t *testing.T) {
	pool := newPoolHistoryTestSimulator(t, poolHistoryTestNow)
	joinedAt := poolHistoryTestNow.Add(37 * time.Minute)

	pool.mu.Lock()
	account := pool.newAccountLocked(joinedAt, true)
	pool.mu.Unlock()

	if !account.FirstSeen.Equal(joinedAt) {
		t.Fatalf("first seen = %s, want exact join time %s", account.FirstSeen, joinedAt)
	}
	if !account.CreatedAt.Equal(joinedAt) {
		t.Fatalf("created at = %s, want exact join time %s", account.CreatedAt, joinedAt)
	}
}

func TestPoolRetirementSeparatesAuthFilesQuotaTombstoneAndHistory(t *testing.T) {
	pool := newPoolHistoryTestSimulator(t, poolHistoryTestNow)
	retiredAt := poolHistoryTestNow.Add(time.Hour)

	pool.mu.Lock()
	account := pool.state.Accounts[0]
	authIndex := account.AuthIndex
	pool.retireLocked(account, retiredAt, "test retirement")
	pool.state.Accounts = pool.state.Accounts[1:]
	pool.mu.Unlock()

	for _, file := range pool.authFiles(retiredAt, false) {
		if file["auth_index"] == authIndex {
			t.Fatal("retired credential leaked into the primary auth-files list")
		}
	}
	if _, ok := pool.usage(retiredAt.Add(14*time.Minute), authIndex); !ok {
		t.Fatal("quota tombstone disappeared before the fifteen-minute grace period")
	}
	if _, ok := pool.profile(retiredAt.Add(14*time.Minute), authIndex); !ok {
		t.Fatal("profile tombstone disappeared before the fifteen-minute grace period")
	}
	if _, ok := pool.usage(retiredAt.Add(poolRetiredGracePeriod), authIndex); !ok {
		t.Fatal("quota tombstone must remain queryable through the grace-period boundary")
	}
	if _, ok := pool.usage(retiredAt.Add(16*time.Minute), authIndex); ok {
		t.Fatal("quota tombstone remained queryable after the fifteen-minute grace period")
	}
	if _, ok := pool.profile(retiredAt.Add(16*time.Minute), authIndex); ok {
		t.Fatal("profile tombstone remained queryable after the fifteen-minute grace period")
	}
	archived, ok := pool.logAccountByAuthIndex(retiredAt.Add(16*time.Minute), authIndex)
	if !ok || archived.AuthIndex != authIndex {
		t.Fatal("minimal history mapping did not outlive the quota tombstone")
	}
	if archived.Current || archived.Plan != "Claude Max" || archived.Status == "" || archived.FirstSeen.IsZero() || archived.RetiredAt.IsZero() {
		t.Fatalf("history card snapshot is incomplete: %#v", archived)
	}
	if archived.Quota.UpdatedAt.IsZero() {
		t.Fatal("history card is missing its safe last-known quota summary")
	}
	encoded, errEncode := json.Marshal(archived)
	if errEncode != nil {
		t.Fatalf("marshal history snapshot: %v", errEncode)
	}
	lower := strings.ToLower(string(encoded))
	for _, forbidden := range []string{"access_token", "refresh_token", "authorization", "oauth_token"} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("history snapshot contains forbidden credential field %q", forbidden)
		}
	}
}

func TestPoolRequestMappingSurvivesChurnCleanupAndReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pool-state.json")
	pool := newPoolSimulator(path, poolHistoryTestNow, 717171)
	// The source request is newer than the simulator's last materialized epoch.
	// A log read must pin its association without advancing that epoch. A later
	// auth-files refresh then catches the pool up across lifecycle churn.
	requestAt := poolHistoryTestNow.Add(6 * time.Hour)
	requestID := "20260819033000123456789abcdef01ABCDEFGH"

	pool.mu.Lock()
	lastEpoch := pool.state.LastEpoch
	revision := pool.state.Revision
	quotaUpdatedAt := pool.state.Accounts[0].UpdatedAt
	quotaUtilization := pool.state.Accounts[0].FiveHour.Utilization
	projectedRoster, projected := pool.mappingRosterAtTimeLocked(requestAt)
	pool.mu.Unlock()
	if !projected || len(projectedRoster) == 0 {
		t.Fatal("could not project the request-time roster")
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("%d|newapi-v1|%s", int64(717171), requestID)))
	expected := projectedRoster[binary.BigEndian.Uint64(sum[:8])%uint64(len(projectedRoster))]
	entry := pool.sourceLogEntry(poolSourceLog{
		SourceID: 1, CreatedAt: requestAt.Unix(), Type: 2,
		Model: "claude-sonnet-5", Status: 200, RequestID: requestID,
	})
	if entry.MappingStatus != "mapped" || entry.AuthIndex == "" {
		t.Fatalf("initial log mapping failed: %#v", entry)
	}
	if entry.AuthIndex != expected.AuthIndex {
		t.Fatalf("initial mapping used %q, want request-time projected account %q", entry.AuthIndex, expected.AuthIndex)
	}
	before, ok := pool.logAccountByAuthIndex(requestAt, entry.AuthIndex)
	if !ok {
		t.Fatal("mapped account is not resolvable")
	}
	pool.mu.Lock()
	if pool.state.LastEpoch != lastEpoch || pool.state.Revision != revision {
		pool.mu.Unlock()
		t.Fatal("log query advanced the pool epoch or revision")
	}
	if !pool.state.Accounts[0].UpdatedAt.Equal(quotaUpdatedAt) || pool.state.Accounts[0].FiveHour.Utilization != quotaUtilization {
		pool.mu.Unlock()
		t.Fatal("log query changed credential quota state")
	}
	if mapping := pool.state.RequestMappings[requestID]; mapping.AuthIndex != before.AuthIndex || !mapping.RequestAt.Equal(requestAt) {
		pool.mu.Unlock()
		t.Fatalf("persisted request mapping = %#v", mapping)
	}
	pool.mu.Unlock()

	// This is the only operation that materializes the pending epochs. The
	// already-observed Request ID must stay pinned to the same projected account.
	pool.authFiles(requestAt, true)
	materializedRoster := pool.rosterAtTime(requestAt)
	if len(materializedRoster) != len(projectedRoster) {
		t.Fatalf("materialized roster length = %d, projected %d", len(materializedRoster), len(projectedRoster))
	}
	for index := range projectedRoster {
		if materializedRoster[index].AuthIndex != projectedRoster[index].AuthIndex {
			t.Fatalf("materialized roster differs from read-only projection at %d", index)
		}
	}

	after, ok := pool.mapRequestAccount(requestAt, requestID)
	if !ok || after.AuthIndex != before.AuthIndex {
		t.Fatalf("mapping changed after churn: %q -> %q", before.AuthIndex, after.AuthIndex)
	}
	if got := len(pool.authFiles(requestAt, false)); got < poolMinimumAccounts || got > poolMaximumAccounts {
		t.Fatalf("primary auth-files count = %d, want %d-%d current credentials", got, poolMinimumAccounts, poolMaximumAccounts)
	}

	reloaded := newPoolSimulator(path, requestAt, 999999)
	persisted, ok := reloaded.mapRequestAccount(requestAt, requestID)
	if !ok || persisted.AuthIndex != before.AuthIndex {
		t.Fatalf("mapping changed after reload: %q -> %q", before.AuthIndex, persisted.AuthIndex)
	}
}

func TestPoolRosterAtTimeIsSortedAndImmutable(t *testing.T) {
	pool := newPoolHistoryTestSimulator(t, poolHistoryTestNow)
	roster := pool.rosterAtTime(poolHistoryTestNow)
	if len(roster) == 0 {
		t.Fatal("expected a roster snapshot")
	}
	if !roster[0].Current || roster[0].Plan != "Claude Max" {
		t.Fatalf("current roster snapshot is incomplete: %#v", roster[0])
	}
	for index := 1; index < len(roster); index++ {
		if roster[index-1].AuthIndex >= roster[index].AuthIndex {
			t.Fatalf("roster is not strictly auth_index sorted at %d", index)
		}
	}
	original := roster[0].AuthIndex
	roster[0].AuthIndex = "mutated-outside-lock"
	second := pool.rosterAtTime(poolHistoryTestNow)
	if second[0].AuthIndex != original {
		t.Fatal("caller mutation changed the simulator's protected account identity")
	}
}

func TestPoolVersionTwoMigrationArchivesAndDropsOldQuotaTombstones(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pool-state.json")
	pool := newPoolSimulator(path, poolHistoryTestNow, 818181)
	retiredAt := poolHistoryTestNow.Add(-time.Hour)

	pool.mu.Lock()
	account := pool.state.Accounts[0]
	authIndex := account.AuthIndex
	pool.retireLocked(account, retiredAt, "v2 migration fixture")
	pool.state.Accounts = pool.state.Accounts[1:]
	pool.state.Version = 2
	pool.state.History = nil
	if err := pool.persistLocked(); err != nil {
		pool.mu.Unlock()
		t.Fatalf("persist v2 fixture: %v", err)
	}
	pool.mu.Unlock()

	reloaded := newPoolSimulator(path, poolHistoryTestNow, 123)
	reloaded.mu.Lock()
	retiredCount := len(reloaded.state.Retired)
	historyCount := len(reloaded.state.History)
	version := reloaded.state.Version
	foundingAt := reloaded.state.Accounts[0].FirstSeen
	activeCount := len(reloaded.state.Accounts)
	reloaded.mu.Unlock()
	if version != poolStateVersion {
		t.Fatalf("state version = %d, want %d", version, poolStateVersion)
	}
	if retiredCount != 0 {
		t.Fatalf("old quota tombstones retained after migration: %d", retiredCount)
	}
	if historyCount != 1 {
		t.Fatalf("history archive count = %d, want 1", historyCount)
	}
	if !foundingAt.Equal(poolHistoryTestNow.Add(-poolHistoryWindow)) {
		t.Fatalf("v2 founding first_seen = %s, want %s", foundingAt, poolHistoryTestNow.Add(-poolHistoryWindow))
	}
	if activeCount < poolMinimumAccounts || activeCount > poolMaximumAccounts {
		t.Fatalf("migrated active count = %d, want %d-%d", activeCount, poolMinimumAccounts, poolMaximumAccounts)
	}
	if _, ok := reloaded.logAccountByAuthIndex(poolHistoryTestNow, authIndex); !ok {
		t.Fatal("migrated history account is not resolvable by auth_index")
	}
}

func TestPoolVersionThreeMigrationPreservesHistoryAwareFirstSeen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pool-state.json")
	pool := newPoolSimulator(path, poolHistoryTestNow, 838383)
	wantFirstSeen := poolHistoryTestNow.Add(-10 * 24 * time.Hour)
	pool.mu.Lock()
	pool.state.Version = 3
	pool.state.Accounts[0].FirstSeen = wantFirstSeen
	pool.state.RequestMappings = nil
	if err := pool.persistLocked(); err != nil {
		pool.mu.Unlock()
		t.Fatalf("persist v3 fixture: %v", err)
	}
	pool.mu.Unlock()

	reloaded := newPoolSimulator(path, poolHistoryTestNow, 123)
	reloaded.mu.Lock()
	version := reloaded.state.Version
	gotFirstSeen := reloaded.state.Accounts[0].FirstSeen
	mappingsInitialized := reloaded.state.RequestMappings != nil
	reloaded.mu.Unlock()
	if version != poolStateVersion {
		t.Fatalf("state version = %d, want %d", version, poolStateVersion)
	}
	if !gotFirstSeen.Equal(wantFirstSeen) {
		t.Fatalf("v3 first_seen changed during v4 migration: %s -> %s", wantFirstSeen, gotFirstSeen)
	}
	if !mappingsInitialized {
		t.Fatal("v3 migration did not initialize request mappings")
	}
}

func TestPoolHistoryExpiresAfterNinetyDays(t *testing.T) {
	pool := newPoolHistoryTestSimulator(t, poolHistoryTestNow)
	pool.mu.Lock()
	account := pool.state.Accounts[0]
	authIndex := account.AuthIndex
	pool.retireLocked(account, poolHistoryTestNow, "history expiry test")
	pool.state.Accounts = pool.state.Accounts[1:]
	pool.cleanupRetiredLocked(poolHistoryTestNow.Add(16 * time.Minute))
	pool.cleanupHistoryLocked(poolHistoryTestNow.Add(poolHistoryWindow + time.Second))
	pool.mu.Unlock()

	if _, ok := pool.logAccountByAuthIndex(poolHistoryTestNow.Add(poolHistoryWindow+time.Second), authIndex); ok {
		t.Fatal("history mapping remained available after the retention window")
	}
}

func TestPoolRequestMappingExpiresAfterNinetyDays(t *testing.T) {
	pool := newPoolHistoryTestSimulator(t, poolHistoryTestNow)
	const requestID = "opaque-request-for-retention"
	if _, ok := pool.mapRequestAccount(poolHistoryTestNow, requestID); !ok {
		t.Fatal("initial request mapping failed")
	}

	pool.mu.Lock()
	if _, exists := pool.state.RequestMappings[requestID]; !exists {
		pool.mu.Unlock()
		t.Fatal("request mapping was not retained")
	}
	pool.cleanupHistoryLocked(poolHistoryTestNow.Add(poolHistoryWindow))
	if _, exists := pool.state.RequestMappings[requestID]; !exists {
		pool.mu.Unlock()
		t.Fatal("request mapping expired at the inclusive retention boundary")
	}
	pool.cleanupHistoryLocked(poolHistoryTestNow.Add(poolHistoryWindow + time.Second))
	if _, exists := pool.state.RequestMappings[requestID]; exists {
		pool.mu.Unlock()
		t.Fatal("request mapping remained after the retention window")
	}
	pool.mu.Unlock()
}

func TestPoolRequestMappingsStayWithinCacheBound(t *testing.T) {
	pool := newPoolHistoryTestSimulator(t, poolHistoryTestNow)
	pool.mu.Lock()
	account := newPoolLogAccount(pool.state.Accounts[0])
	pool.state.RequestMappings = make(map[string]poolRequestMapping, poolMaximumRequestMappings+5)
	for index := 0; index < poolMaximumRequestMappings+5; index++ {
		requestID := fmt.Sprintf("bounded-request-%05d", index)
		pool.state.RequestMappings[requestID] = poolRequestMapping{
			AuthIndex: account.AuthIndex,
			RequestAt: poolHistoryTestNow.Add(time.Duration(index) * time.Second),
			Account:   account,
		}
	}
	changed := pool.trimRequestMappingsLocked(poolHistoryTestNow.Add(time.Duration(poolMaximumRequestMappings+5) * time.Second))
	count := len(pool.state.RequestMappings)
	_, oldestExists := pool.state.RequestMappings["bounded-request-00000"]
	_, newestExists := pool.state.RequestMappings[fmt.Sprintf("bounded-request-%05d", poolMaximumRequestMappings+4)]
	pool.mu.Unlock()

	if !changed || count != poolMaximumRequestMappings {
		t.Fatalf("trimmed mapping count = %d, changed=%v", count, changed)
	}
	if oldestExists || !newestExists {
		t.Fatal("mapping bound did not evict the oldest association first")
	}
}

func TestPoolRequestMappingRetriesPersistenceAfterTransientFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pool-state.json")
	pool := newPoolSimulator(path, poolHistoryTestNow, 424242)
	const requestID = "mapping-persistence-retry"

	// Renaming a state file over an existing directory fails after the mapping
	// has been created in memory, reproducing a transient atomic-write failure.
	failingPath := t.TempDir()
	pool.mu.Lock()
	pool.path = failingPath
	pool.mu.Unlock()
	if _, ok := pool.mapRequestAccount(poolHistoryTestNow, requestID); !ok {
		t.Fatal("mapping failed when persistence was unavailable")
	}
	pool.mu.Lock()
	dirtyAfterFailure := pool.mappingDirty
	pool.path = path
	pool.mu.Unlock()
	if !dirtyAfterFailure {
		t.Fatal("failed mapping persistence was not marked dirty")
	}

	// The second lookup is an in-memory hit, but must still retry the pending
	// atomic write so a subsequent process can recover exactly the same mapping.
	want, ok := pool.mapRequestAccount(poolHistoryTestNow, requestID)
	if !ok {
		t.Fatal("mapping retry failed")
	}
	reloaded := newPoolSimulator(path, poolHistoryTestNow, 999999)
	got, ok := reloaded.mapRequestAccount(poolHistoryTestNow, requestID)
	if !ok || got.AuthIndex != want.AuthIndex {
		t.Fatalf("mapping was not recovered after persistence retry: %q -> %q", want.AuthIndex, got.AuthIndex)
	}
}

func TestPoolRequestMappingSnapshotRejectsUnsafePlan(t *testing.T) {
	pool := newPoolHistoryTestSimulator(t, poolHistoryTestNow)
	const requestID = "mapping-safe-snapshot"
	account, ok := pool.mapRequestAccount(poolHistoryTestNow, requestID)
	if !ok {
		t.Fatal("initial request mapping failed")
	}
	if account.Email == "" || !strings.Contains(account.Email, "*") {
		t.Fatalf("mapping exposed an unmasked email: %q", account.Email)
	}

	pool.mu.Lock()
	mapping := pool.state.RequestMappings[requestID]
	mapping.Account.Plan = "complete.address@gmail.com"
	pool.state.RequestMappings[requestID] = mapping
	errValidate := validatePoolPersistentState(&pool.state)
	pool.mu.Unlock()
	if errValidate == nil {
		t.Fatal("unsafe mapping plan passed persistent-state validation")
	}
}

func TestPoolModelsUseFixedFourModelSnapshot(t *testing.T) {
	models := poolModelsForAuth("anything")
	want := []string{
		"claude-fable-5",
		"claude-opus-4-8",
		"claude-sonnet-5",
		"claude-haiku-4-5-20251001",
	}
	if len(models) != len(want) {
		t.Fatalf("model count = %d, want %d", len(models), len(want))
	}
	for index, model := range models {
		if got := model["id"]; got != want[index] {
			t.Fatalf("model %d = %q, want %q", index, got, want[index])
		}
	}
}

func TestPoolRequestMappingIsConcurrentAndStable(t *testing.T) {
	pool := newPoolHistoryTestSimulator(t, poolHistoryTestNow)
	const requestID = "20260819040000987654321abcdef01HGFEDCBA"
	want, ok := pool.mapRequestAccount(poolHistoryTestNow, requestID)
	if !ok {
		t.Fatal("initial request mapping failed")
	}

	var wait sync.WaitGroup
	errors := make(chan string, 32)
	for index := 0; index < cap(errors); index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			got, found := pool.mapRequestAccount(poolHistoryTestNow, requestID)
			if !found || got.AuthIndex != want.AuthIndex {
				errors <- got.AuthIndex
			}
		}()
	}
	wait.Wait()
	close(errors)
	for got := range errors {
		t.Fatalf("concurrent mapping = %q, want %q", got, want.AuthIndex)
	}
}
