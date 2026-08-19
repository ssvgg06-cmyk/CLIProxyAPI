package management

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestBridgePoolLogSourceUsesBearerAndOpaqueRequestID(t *testing.T) {
	requestID := " opaque / request?id=1 "
	var seenPath string
	var seenQuery url.Values
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer bridge-secret" {
			t.Fatalf("authorization header = %q", request.Header.Get("Authorization"))
		}
		seenPath = request.URL.Path
		seenQuery = request.URL.Query()
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(map[string]any{
			"items": []map[string]any{{
				"source_id":           42,
				"created_at":          1787068800,
				"type":                2,
				"model_name":          "claude-future-model",
				"status":              200,
				"latency_ms":          12345,
				"request_id":          requestID,
				"upstream_request_id": "upstream.opaque",
				"username":            "must-not-be-decoded",
				"content":             "must-not-be-decoded",
			}},
			"has_more": false,
		})
	}))
	defer server.Close()

	source, errSource := newBridgePoolLogSource(server.URL+"/internal/cpa", "bridge-secret", server.Client())
	if errSource != nil {
		t.Fatalf("create bridge source: %v", errSource)
	}
	page, errLookup := source.Lookup(context.Background(), requestID)
	if errLookup != nil {
		t.Fatalf("lookup: %v", errLookup)
	}
	if seenPath != "/internal/cpa/v1/logs/lookup" || seenQuery.Get("request_id") != requestID {
		t.Fatalf("request = %s?%s", seenPath, seenQuery.Encode())
	}
	if len(page.Items) != 1 || page.Items[0].RequestID != requestID {
		t.Fatalf("lookup page = %#v", page)
	}
}

func TestBridgePoolLogSourceRequiresHTTPSExceptLoopback(t *testing.T) {
	if _, errSource := newBridgePoolLogSource("http://example.com/internal", "secret", nil); errSource == nil {
		t.Fatal("cleartext non-loopback bridge URL must be rejected")
	}
	for _, rawURL := range []string{"http://localhost:8080", "http://127.0.0.1:8080", "http://[::1]:8080", "https://example.com"} {
		if _, errSource := newBridgePoolLogSource(rawURL, "secret", &http.Client{}); errSource != nil {
			t.Fatalf("URL %q rejected: %v", rawURL, errSource)
		}
	}
}

func TestBridgePoolLogSourceDoesNotFollowRedirects(t *testing.T) {
	redirected := false
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		redirected = true
	}))
	defer destination.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer origin.Close()

	source, errSource := newBridgePoolLogSource(origin.URL, "bridge-secret", origin.Client())
	if errSource != nil {
		t.Fatalf("create bridge source: %v", errSource)
	}
	if _, errLookup := source.Lookup(context.Background(), "opaque-request"); errLookup == nil {
		t.Fatal("redirect response must not be followed")
	}
	if redirected {
		t.Fatal("bearer request reached redirect destination")
	}
}

type fakePoolLogSource struct {
	mu          sync.Mutex
	items       []poolSourceLog
	err         error
	searchCalls int
	lookupCalls int
	changeCalls int
}

type cursorCheckingPoolLogSource struct {
	t     *testing.T
	now   time.Time
	calls int
}

func (s *cursorCheckingPoolLogSource) Changes(context.Context, int64, int) (poolLogSourcePage, error) {
	return poolLogSourcePage{}, nil
}

func (s *cursorCheckingPoolLogSource) Search(_ context.Context, _, _ time.Time, beforeID int64, _ int) (poolLogSourcePage, error) {
	s.t.Helper()
	s.calls++
	switch s.calls {
	case 1:
		if beforeID != 0 {
			s.t.Fatalf("first before_id = %d, want 0", beforeID)
		}
		first := poolCacheTestRecord(7, "cursor-newest", "")
		first.CreatedAt = s.now.Add(-time.Minute).Unix()
		second := poolCacheTestRecord(99, "cursor-page-end", "")
		second.CreatedAt = s.now.Add(-2 * time.Minute).Unix()
		return poolLogSourcePage{
			Items:        []poolSourceLog{first, second},
			NextBeforeID: 99,
			HasMore:      true,
		}, nil
	case 2:
		if beforeID != 99 {
			s.t.Fatalf("second before_id = %d, want last composite-ordered ID 99", beforeID)
		}
		last := poolCacheTestRecord(50, "cursor-oldest", "")
		last.CreatedAt = s.now.Add(-3 * time.Minute).Unix()
		return poolLogSourcePage{Items: []poolSourceLog{last}}, nil
	default:
		s.t.Fatalf("unexpected search call %d", s.calls)
		return poolLogSourcePage{}, nil
	}
}

func (s *cursorCheckingPoolLogSource) Lookup(context.Context, string) (poolLogSourcePage, error) {
	return poolLogSourcePage{}, nil
}

func (f *fakePoolLogSource) Changes(_ context.Context, afterID int64, limit int) (poolLogSourcePage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.changeCalls++
	if f.err != nil {
		return poolLogSourcePage{}, f.err
	}
	items := make([]poolSourceLog, 0, limit)
	next := afterID
	for _, item := range f.items {
		if item.SourceID <= afterID {
			continue
		}
		items = append(items, item)
		if item.SourceID > next {
			next = item.SourceID
		}
		if len(items) >= limit {
			break
		}
	}
	return poolLogSourcePage{Items: items, NextAfterID: next, HasMore: len(items) == limit}, nil
}

func (f *fakePoolLogSource) Search(_ context.Context, from, to time.Time, beforeID int64, limit int) (poolLogSourcePage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.searchCalls++
	if f.err != nil {
		return poolLogSourcePage{}, f.err
	}
	items := make([]poolSourceLog, 0, limit)
	for index := len(f.items) - 1; index >= 0; index-- {
		item := f.items[index]
		if item.CreatedAt < from.Unix() || item.CreatedAt > to.Unix() || beforeID > 0 && item.SourceID >= beforeID {
			continue
		}
		items = append(items, item)
		if len(items) >= limit {
			break
		}
	}
	nextBefore := int64(0)
	for _, item := range items {
		if nextBefore == 0 || item.SourceID < nextBefore {
			nextBefore = item.SourceID
		}
	}
	return poolLogSourcePage{Items: items, NextBeforeID: nextBefore, HasMore: len(items) == limit}, nil
}

func (f *fakePoolLogSource) Lookup(_ context.Context, requestID string) (poolLogSourcePage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lookupCalls++
	if f.err != nil {
		return poolLogSourcePage{}, f.err
	}
	for _, item := range f.items {
		if item.RequestID == requestID {
			return poolLogSourcePage{Items: []poolSourceLog{item}}, nil
		}
	}
	items := make([]poolSourceLog, 0)
	for _, item := range f.items {
		if item.UpstreamID == requestID {
			items = append(items, item)
		}
	}
	return poolLogSourcePage{Items: items}, nil
}

func installPoolLogTestService(t *testing.T, pool *poolSimulator, source poolLogSource, now time.Time) *poolLogService {
	t.Helper()
	service := &poolLogService{
		pool:       pool,
		source:     source,
		cache:      newPoolLogCache("", poolLogCacheMaxEntries),
		configured: true,
		now:        func() time.Time { return now },
	}
	poolLogServiceRegistry.Store(pool, service)
	t.Cleanup(func() { poolLogServiceRegistry.Delete(pool) })
	return service
}

func TestPoolLogPrimeUsesBridgeCompositeCursor(t *testing.T) {
	now := time.Date(2026, 8, 19, 8, 0, 0, 0, time.UTC)
	source := &cursorCheckingPoolLogSource{t: t, now: now}
	service := &poolLogService{
		source:     source,
		cache:      newPoolLogCache("", poolLogCacheMaxEntries),
		configured: true,
		now:        func() time.Time { return now },
	}
	if errPrime := service.prime(context.Background(), now); errPrime != nil {
		t.Fatalf("prime: %v", errPrime)
	}
	if source.calls != 2 {
		t.Fatalf("search calls = %d, want 2", source.calls)
	}
	items := service.cache.query(now.Add(-poolLogPrimeWindow), now, 10)
	if len(items) != 3 {
		t.Fatalf("cached items = %d, want 3", len(items))
	}
}

func TestPoolLogQueryUsesRealSourceWithoutAdvancingPool(t *testing.T) {
	now := time.Date(2026, 8, 19, 8, 0, 0, 0, time.UTC)
	pool := newPoolSimulator(filepath.Join(t.TempDir(), "pool-state.json"), now, 424242)
	items := []poolSourceLog{
		poolCacheTestRecord(101, "opaque-a", "upstream-shared"),
		poolCacheTestRecord(102, "opaque-b", "upstream-shared"),
		poolCacheTestRecord(103, "short-id", "upstream-c"),
	}
	for index := range items {
		items[index].CreatedAt = now.Add(-time.Duration(3-index) * time.Minute).Unix()
	}
	source := &fakePoolLogSource{items: items}
	installPoolLogTestService(t, pool, source, now)

	pool.mu.Lock()
	revisionBefore := pool.state.Revision
	pool.mu.Unlock()
	entries, total, _, truncated, errQuery := pool.queryLogsWithContext(context.Background(), now, poolLogFilter{
		From: now.Add(-time.Hour), To: now, Limit: 1,
	})
	if errQuery != nil {
		t.Fatalf("query logs: %v", errQuery)
	}
	if total != 3 || len(entries) != 1 || !truncated {
		t.Fatalf("query = total:%d entries:%d truncated:%v", total, len(entries), truncated)
	}
	entry := entries[0]
	if entry.Source != "newapi" || entry.MappingStatus != "mapped" || entry.RequestID != "short-id" || entry.AuthIndex == "" {
		t.Fatalf("mapped entry = %#v", entry)
	}
	pool.mu.Lock()
	revisionAfter := pool.state.Revision
	pool.mu.Unlock()
	if revisionAfter != revisionBefore {
		t.Fatalf("log read advanced pool revision from %d to %d", revisionBefore, revisionAfter)
	}

	upstream, _, _, _, errLookup := pool.queryLogsWithContext(context.Background(), now, poolLogFilter{
		RequestID: "upstream-shared", Limit: 100,
	})
	if errLookup != nil || len(upstream) != 2 {
		t.Fatalf("upstream lookup = %d entries, err %v", len(upstream), errLookup)
	}
	for _, result := range upstream {
		if result.UpstreamID != "upstream-shared" || result.MappingStatus != "mapped" {
			t.Fatalf("upstream result = %#v", result)
		}
	}
}

func TestPoolLogSourceKeepsUnmappedRealRecord(t *testing.T) {
	now := time.Date(2026, 8, 19, 8, 0, 0, 0, time.UTC)
	pool := newPoolSimulator(filepath.Join(t.TempDir(), "pool-state.json"), now, 424242)
	entry := pool.sourceLogEntry(poolSourceLog{
		SourceID: 1, CreatedAt: 1, Type: 5, Model: "claude-opus-5", Status: 500,
		LatencyMS: 999999999, RequestID: "opaque-unmapped",
	})
	if entry.RequestID != "opaque-unmapped" || entry.Source != "newapi" || entry.MappingStatus != "unmapped" {
		t.Fatalf("unmapped record was dropped or altered: %#v", entry)
	}
	if entry.AuthIndex != "" || entry.LatencyMS != 999999999 {
		t.Fatalf("unmapped fields = %#v", entry)
	}
}

func TestPoolLogSourceFailureUsesCacheAndMarksStale(t *testing.T) {
	now := time.Date(2026, 8, 19, 8, 0, 0, 0, time.UTC)
	pool := newPoolSimulator(filepath.Join(t.TempDir(), "pool-state.json"), now, 424242)
	source := &fakePoolLogSource{err: errors.New("bridge down")}
	service := installPoolLogTestService(t, pool, source, now)
	record := poolCacheTestRecord(1, "cached-opaque", "")
	record.CreatedAt = now.Add(-time.Minute).Unix()
	service.cache.add([]poolSourceLog{record}, now.Add(-time.Hour))
	service.cache.markSuccess(now.Add(-time.Hour), 1)

	entries, _, _, _, errQuery := pool.queryLogsWithContext(context.Background(), now, poolLogFilter{
		From: now.Add(-time.Hour), To: now, Limit: 10,
	})
	if errQuery == nil || len(entries) != 1 || entries[0].RequestID != "cached-opaque" {
		t.Fatalf("stale query = entries:%#v err:%v", entries, errQuery)
	}
	metadata := service.metadata(now)
	if !metadata.Stale || metadata.Available || metadata.Status != "unavailable" {
		t.Fatalf("metadata = %#v", metadata)
	}

	// The failure starts a backoff window; a second uncached exact lookup must
	// fail closed without hammering the bridge or fabricating a record.
	source.mu.Lock()
	callsBefore := source.lookupCalls
	source.mu.Unlock()
	if results, errLookup := service.lookup(context.Background(), "not-cached"); errLookup == nil || len(results) != 0 {
		t.Fatalf("lookup during backoff = %#v, %v", results, errLookup)
	}
	source.mu.Lock()
	callsAfter := source.lookupCalls
	source.mu.Unlock()
	if callsAfter != callsBefore {
		t.Fatalf("bridge calls during backoff changed from %d to %d", callsBefore, callsAfter)
	}
}

func TestPoolLogLookupUsesBridgePrimaryBeforeCachedUpstream(t *testing.T) {
	now := time.Date(2026, 8, 19, 8, 0, 0, 0, time.UTC)
	pool := newPoolSimulator(filepath.Join(t.TempDir(), "pool-state.json"), now, 424242)
	primary := poolCacheTestRecord(2, "shared-id", "")
	primary.CreatedAt = now.Add(-time.Minute).Unix()
	service := installPoolLogTestService(t, pool, &fakePoolLogSource{items: []poolSourceLog{primary}}, now)
	cachedUpstream := poolCacheTestRecord(1, "different-primary", "shared-id")
	cachedUpstream.CreatedAt = now.Add(-2 * time.Minute).Unix()
	service.cache.add([]poolSourceLog{cachedUpstream}, now)

	items, errLookup := service.lookup(context.Background(), "shared-id")
	if errLookup != nil {
		t.Fatalf("lookup: %v", errLookup)
	}
	if len(items) != 1 || items[0].SourceID != primary.SourceID {
		t.Fatalf("lookup = %#v, want bridge primary only", items)
	}
}

func TestPoolRecentErrorsFilterBeforeApplyingFileLimit(t *testing.T) {
	now := time.Date(2026, 8, 19, 8, 0, 0, 0, time.UTC)
	pool := newPoolSimulator(filepath.Join(t.TempDir(), "pool-state.json"), now, 424242)
	items := make([]poolSourceLog, 0, 301)
	failure := poolCacheTestRecord(1, "oldest-real-error", "")
	failure.Type = 5
	failure.Status = 502
	failure.CreatedAt = now.Add(-10 * time.Minute).Unix()
	items = append(items, failure)
	for index := int64(2); index <= 301; index++ {
		record := poolCacheTestRecord(index, fmt.Sprintf("success-%d", index), "")
		record.CreatedAt = now.Add(-time.Duration(302-index) * time.Second).Unix()
		items = append(items, record)
	}
	installPoolLogTestService(t, pool, &fakePoolLogSource{items: items}, now)

	errors := pool.recentErrorEntries(now, time.Hour, 200)
	if len(errors) != 1 || errors[0].RequestID != failure.RequestID {
		t.Fatalf("recent errors = %#v, want the type-5 record before the 200-file cap", errors)
	}
}

func TestReadPoolLogSourceTokenRejectsOversize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bridge-token")
	if errWrite := os.WriteFile(path, []byte(strings.Repeat("x", 4097)), 0o600); errWrite != nil {
		t.Fatalf("write token: %v", errWrite)
	}
	if _, errToken := readPoolLogSourceToken(path); errToken == nil {
		t.Fatal("oversize token must be rejected")
	}
}
