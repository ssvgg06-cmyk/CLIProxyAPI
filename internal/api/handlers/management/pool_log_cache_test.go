package management

import (
	"compress/gzip"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func poolCacheTestRecord(sourceID int64, requestID, upstreamID string) poolSourceLog {
	createdAt := time.Now().UTC().Add(-time.Hour).Truncate(time.Minute).Add(time.Duration(sourceID%60) * time.Second)
	return poolSourceLog{
		SourceID:   sourceID,
		CreatedAt:  createdAt.Unix(),
		Type:       2,
		Model:      "claude-opus-5",
		Status:     200,
		LatencyMS:  7123,
		RequestID:  requestID,
		UpstreamID: upstreamID,
	}
}

func TestPoolLogCachePrimaryLookupWinsAndUpstreamReturnsAll(t *testing.T) {
	cache := newPoolLogCache("", 10)
	now := time.Now().UTC()
	cache.add([]poolSourceLog{
		poolCacheTestRecord(1, "primary-one", "shared-upstream"),
		poolCacheTestRecord(2, "shared-upstream", "another-upstream"),
		poolCacheTestRecord(3, "primary-three", "shared-upstream"),
	}, now)

	primary := cache.lookup("shared-upstream")
	if len(primary) != 1 || primary[0].SourceID != 2 {
		t.Fatalf("primary lookup = %#v, want only source 2", primary)
	}

	upstream := cache.lookup("another-upstream")
	if len(upstream) != 1 || upstream[0].SourceID != 2 {
		t.Fatalf("upstream lookup = %#v, want source 2", upstream)
	}

	sharedOnly := newPoolLogCache("", 10)
	sharedOnly.add([]poolSourceLog{
		poolCacheTestRecord(1, "primary-one", "shared-upstream"),
		poolCacheTestRecord(3, "primary-three", "shared-upstream"),
	}, now)
	upstream = sharedOnly.lookup("shared-upstream")
	if len(upstream) != 2 || upstream[0].SourceID != 1 || upstream[1].SourceID != 3 {
		t.Fatalf("shared upstream lookup = %#v, want sources 1 and 3", upstream)
	}
}

func TestPoolLogCacheReindexesUpdatedSourceRecord(t *testing.T) {
	cache := newPoolLogCache("", 10)
	now := time.Now().UTC()
	cache.add([]poolSourceLog{poolCacheTestRecord(1, "old-request", "old-upstream")}, now)
	cache.add([]poolSourceLog{poolCacheTestRecord(1, "new-request", "new-upstream")}, now.Add(time.Second))

	if found := cache.lookup("old-request"); len(found) != 0 {
		t.Fatalf("stale primary index survived update: %#v", found)
	}
	if found := cache.lookup("old-upstream"); len(found) != 0 {
		t.Fatalf("stale upstream index survived update: %#v", found)
	}
	if found := cache.lookup("new-request"); len(found) != 1 || found[0].SourceID != 1 {
		t.Fatalf("updated primary lookup = %#v", found)
	}
}

func TestPoolLogCacheDeduplicatesPrimaryRequestID(t *testing.T) {
	cache := newPoolLogCache("", 10)
	now := time.Now().UTC()
	cache.add([]poolSourceLog{
		poolCacheTestRecord(1, "same-request", "first-upstream"),
		poolCacheTestRecord(2, "same-request", "second-upstream"),
	}, now)

	found := cache.lookup("same-request")
	if len(found) != 1 || found[0].SourceID != 2 {
		t.Fatalf("primary deduplication = %#v, want newest source record", found)
	}
	if old := cache.lookup("first-upstream"); len(old) != 0 {
		t.Fatalf("discarded duplicate remained in upstream index: %#v", old)
	}
}

func TestPoolLogCacheRequiresExplicitCompleteCoverage(t *testing.T) {
	cache := newPoolLogCache("", 10)
	now := time.Now().UTC().Truncate(time.Second)
	record := poolCacheTestRecord(1, "isolated-lookup", "")
	record.CreatedAt = now.Add(-time.Hour).Unix()
	cache.add([]poolSourceLog{record}, now)
	cache.markSuccess(now, 0)

	from := now.Add(-2 * time.Hour)
	if cache.covers(from, now) {
		t.Fatal("an isolated exact lookup must not imply complete range coverage")
	}
	cache.markCoverage(from, now)
	if !cache.covers(from, now) {
		t.Fatal("a completely fetched range should be covered")
	}
}

func TestPoolLogCacheEmptyCacheCannotClaimCoverage(t *testing.T) {
	cache := newPoolLogCache("", 10)
	now := time.Now().UTC().Truncate(time.Second)
	cache.markSuccess(now, 0)
	cache.markCoverage(now.Add(-time.Hour), now)
	if cache.covers(now.Add(-time.Hour), now) {
		t.Fatal("an empty cache must not claim complete range coverage")
	}
}

func TestPoolLogCacheCapsAndRoundTripsGzip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "newapi-log-cache.json.gz")
	cache := newPoolLogCache(path, 3)
	now := time.Now().UTC().Truncate(time.Second)
	cache.add([]poolSourceLog{
		poolCacheTestRecord(1, "opaque-one", ""),
		poolCacheTestRecord(2, "opaque-two", ""),
		poolCacheTestRecord(3, "opaque-three", ""),
		poolCacheTestRecord(4, "opaque-four", ""),
	}, now)
	cache.markSuccess(now, 4)
	if errPersist := cache.persist(); errPersist != nil {
		t.Fatalf("persist cache: %v", errPersist)
	}

	info, errStat := os.Stat(path)
	if errStat != nil {
		t.Fatalf("stat cache: %v", errStat)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("cache mode = %o, want 600", info.Mode().Perm())
	}

	reloaded := newPoolLogCache(path, 3)
	entries, cursor, lastSuccess := reloaded.stats()
	if entries != 3 || cursor != 4 || !lastSuccess.Equal(now) {
		t.Fatalf("reloaded stats = entries:%d cursor:%d success:%v", entries, cursor, lastSuccess)
	}
	if len(reloaded.lookup("opaque-one")) != 0 {
		t.Fatal("oldest item should have been trimmed")
	}
	if found := reloaded.lookup("opaque-four"); len(found) != 1 || found[0].SourceID != 4 {
		t.Fatalf("reloaded lookup = %#v", found)
	}
}

func TestPoolLogCacheDiscardsSnapshotFromBeforeMaxGroupFilter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "newapi-log-cache.json.gz")
	now := time.Now().UTC().Truncate(time.Second)
	record := poolCacheTestRecord(41, "pre-max-filter-request", "")
	record.CreatedAt = now.Add(-time.Minute).Unix()
	writePoolLogCacheSnapshot(t, path, poolLogCacheSnapshot{
		Version:     poolLogCacheVersion - 1,
		AfterID:     record.SourceID,
		UpdatedAt:   now.Unix(),
		LastSuccess: now.Unix(),
		Items:       []poolSourceLog{record},
	})

	cache := newPoolLogCache(path, 10)
	entries, cursor, lastSuccess := cache.stats()
	if entries != 0 || cursor != 0 || !lastSuccess.IsZero() {
		t.Fatalf("pre-filter cache survived version migration: entries=%d cursor=%d last_success=%v", entries, cursor, lastSuccess)
	}
}

func TestPoolLogCacheRejectsUnsafeRecordsAndDoesNotClampLatency(t *testing.T) {
	hugeLatency := int64(12_140_000)
	accepted, ok := sanitizePoolSourceLog(poolSourceLog{
		SourceID:  1,
		CreatedAt: time.Now().Unix(),
		Type:      2,
		Model:     "claude-future-model",
		Status:    200,
		LatencyMS: hugeLatency,
		RequestID: "opaque.request:id-36",
	})
	if !ok || accepted.LatencyMS != hugeLatency {
		t.Fatalf("safe Claude record rejected or latency clamped: %#v, %v", accepted, ok)
	}

	unsafe := accepted
	unsafe.RequestID = "line\nbreak"
	if _, ok = sanitizePoolSourceLog(unsafe); ok {
		t.Fatal("request ID containing a control character must be rejected")
	}
	unsafe = accepted
	unsafe.Model = "gpt-5"
	if _, ok = sanitizePoolSourceLog(unsafe); ok {
		t.Fatal("non-Claude record must be rejected")
	}
}

func writePoolLogCacheSnapshot(t *testing.T, path string, snapshot poolLogCacheSnapshot) {
	t.Helper()
	file, errCreate := os.Create(path)
	if errCreate != nil {
		t.Fatalf("create cache fixture: %v", errCreate)
	}
	compressed := gzip.NewWriter(file)
	if errEncode := json.NewEncoder(compressed).Encode(snapshot); errEncode != nil {
		_ = compressed.Close()
		_ = file.Close()
		t.Fatalf("encode cache fixture: %v", errEncode)
	}
	if errClose := compressed.Close(); errClose != nil {
		_ = file.Close()
		t.Fatalf("close cache fixture gzip: %v", errClose)
	}
	if errClose := file.Close(); errClose != nil {
		t.Fatalf("close cache fixture: %v", errClose)
	}
}

func TestPoolLogCacheDiscardsSemanticallyCorruptSnapshots(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	record := poolCacheTestRecord(41, "valid-primary", "valid-upstream")
	record.CreatedAt = now.Add(-30 * time.Minute).Unix()
	valid := poolLogCacheSnapshot{
		Version:         poolLogCacheVersion,
		AfterID:         record.SourceID,
		UpdatedAt:       now.Unix(),
		LastSuccess:     now.Unix(),
		CoverageFrom:    now.Add(-time.Hour).Unix(),
		CoverageThrough: now.Unix(),
		Items:           []poolSourceLog{record},
	}

	tests := []struct {
		name   string
		mutate func(*poolLogCacheSnapshot)
	}{
		{
			name: "oversized cursor",
			mutate: func(snapshot *poolLogCacheSnapshot) {
				snapshot.AfterID = math.MaxInt64
			},
		},
		{
			name: "cursor ahead of records",
			mutate: func(snapshot *poolLogCacheSnapshot) {
				snapshot.AfterID = record.SourceID + 1
			},
		},
		{
			name: "future last success",
			mutate: func(snapshot *poolLogCacheSnapshot) {
				snapshot.LastSuccess = now.Add(time.Hour).Unix()
			},
		},
		{
			name: "empty cache with fake coverage",
			mutate: func(snapshot *poolLogCacheSnapshot) {
				snapshot.AfterID = 0
				snapshot.UpdatedAt = 0
				snapshot.Items = nil
			},
		},
		{
			name: "one sided coverage",
			mutate: func(snapshot *poolLogCacheSnapshot) {
				snapshot.CoverageThrough = 0
			},
		},
		{
			name: "coverage without matching item",
			mutate: func(snapshot *poolLogCacheSnapshot) {
				snapshot.CoverageFrom = now.Add(-2 * time.Hour).Unix()
				snapshot.CoverageThrough = now.Add(-time.Hour).Unix()
			},
		},
		{
			name: "record newer than update",
			mutate: func(snapshot *poolLogCacheSnapshot) {
				snapshot.UpdatedAt = now.Add(-2 * time.Hour).Unix()
			},
		},
		{
			name: "noncanonical record",
			mutate: func(snapshot *poolLogCacheSnapshot) {
				snapshot.Items[0].Status = 0
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := valid
			snapshot.Items = append([]poolSourceLog(nil), valid.Items...)
			test.mutate(&snapshot)
			path := filepath.Join(t.TempDir(), "newapi-log-cache.json.gz")
			writePoolLogCacheSnapshot(t, path, snapshot)

			cache := newPoolLogCache(path, 10)
			entries, cursor, lastSuccess := cache.stats()
			if entries != 0 || cursor != 0 || !lastSuccess.IsZero() {
				t.Fatalf("corrupt snapshot was retained: entries=%d cursor=%d last_success=%v", entries, cursor, lastSuccess)
			}
			if cache.covers(now.Add(-time.Hour), now) {
				t.Fatal("corrupt snapshot retained range coverage")
			}
		})
	}
}

func TestPoolLogCacheStrictSnapshotValidationAcceptsLookupAheadOfCursor(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	first := poolCacheTestRecord(41, "incremental-primary", "")
	first.CreatedAt = now.Add(-time.Hour).Unix()
	lookup := poolCacheTestRecord(99, "lookup-primary", "")
	lookup.CreatedAt = now.Add(-time.Minute).Unix()
	path := filepath.Join(t.TempDir(), "newapi-log-cache.json.gz")
	writePoolLogCacheSnapshot(t, path, poolLogCacheSnapshot{
		Version:     poolLogCacheVersion,
		AfterID:     first.SourceID,
		UpdatedAt:   now.Unix(),
		LastSuccess: now.Unix(),
		Items:       []poolSourceLog{first, lookup},
	})

	cache := newPoolLogCache(path, 10)
	entries, cursor, lastSuccess := cache.stats()
	if entries != 2 || cursor != first.SourceID || !lastSuccess.Equal(now) {
		t.Fatalf("valid lookup-ahead snapshot rejected: entries=%d cursor=%d last_success=%v", entries, cursor, lastSuccess)
	}
}
