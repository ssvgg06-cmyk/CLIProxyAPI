package management

import (
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	// Version 2 invalidates records cached before the bridge was restricted to
	// the New API max group.
	poolLogCacheVersion    = 2
	poolLogCacheMaxEntries = 20000
	poolLogCacheMaxBytes   = 64 << 20
	// Source identifiers are serialized as JSON numbers in the bridge protocol.
	// Keeping persisted cursors inside the exact-integer range prevents a
	// tampered cache from parking incremental synchronization at MaxInt64 (or a
	// similarly implausible value) indefinitely.
	poolLogCacheMaxSourceID = int64(1<<53 - 1)
	poolLogCacheFutureSkew  = 5 * time.Minute
)

// poolSourceLog is the deliberately small, privacy-safe record accepted from
// the New API log bridge. It must never grow fields containing users, tokens,
// channels, IP addresses, raw content, or arbitrary upstream metadata.
type poolSourceLog struct {
	SourceID   int64  `json:"source_id"`
	CreatedAt  int64  `json:"created_at"`
	Type       int    `json:"type"`
	Model      string `json:"model_name"`
	Status     int    `json:"status"`
	LatencyMS  int64  `json:"latency_ms"`
	RequestID  string `json:"request_id"`
	UpstreamID string `json:"upstream_request_id,omitempty"`
}

type poolLogCacheSnapshot struct {
	Version         int             `json:"version"`
	AfterID         int64           `json:"after_id"`
	UpdatedAt       int64           `json:"updated_at"`
	LastSuccess     int64           `json:"last_success"`
	CoverageFrom    int64           `json:"coverage_from,omitempty"`
	CoverageThrough int64           `json:"coverage_through,omitempty"`
	Items           []poolSourceLog `json:"items"`
}

// poolLogCache stores only scrubbed bridge records. Items are kept in source
// identifier order so trimming and incremental resumption are deterministic.
type poolLogCache struct {
	mu              sync.RWMutex
	path            string
	maxEntries      int
	afterID         int64
	updatedAt       time.Time
	lastSuccess     time.Time
	coverageFrom    time.Time
	coverageThrough time.Time
	items           []poolSourceLog
	bySourceID      map[int64]int
	byRequestID     map[string]int
	byUpstreamID    map[string][]int
	dirty           bool
	revision        uint64
}

func newPoolLogCache(path string, maxEntries int) *poolLogCache {
	if maxEntries <= 0 {
		maxEntries = poolLogCacheMaxEntries
	}
	cache := &poolLogCache{
		path:         strings.TrimSpace(path),
		maxEntries:   maxEntries,
		bySourceID:   make(map[int64]int, maxEntries),
		byRequestID:  make(map[string]int, maxEntries),
		byUpstreamID: make(map[string][]int, maxEntries),
	}
	if errLoad := cache.load(); errLoad != nil && !os.IsNotExist(errLoad) {
		// A corrupt cache is disposable. The authoritative copy stays in New API.
		// The caller reports source availability separately and can safely refill it.
		log.WithError(errLoad).Warn("discarding unreadable New API pool log cache")
		cache.items = nil
		cache.afterID = 0
		cache.updatedAt = time.Time{}
		cache.lastSuccess = time.Time{}
		cache.coverageFrom = time.Time{}
		cache.coverageThrough = time.Time{}
		cache.rebuildIndexesLocked()
	}
	return cache
}

func (c *poolLogCache) load() error {
	if c == nil || c.path == "" {
		return os.ErrNotExist
	}
	file, errOpen := os.Open(c.path)
	if errOpen != nil {
		return errOpen
	}
	defer func() { _ = file.Close() }()

	compressed, errGzip := gzip.NewReader(io.LimitReader(file, poolLogCacheMaxBytes))
	if errGzip != nil {
		return fmt.Errorf("open pool log cache: %w", errGzip)
	}
	defer func() { _ = compressed.Close() }()

	var snapshot poolLogCacheSnapshot
	decoder := json.NewDecoder(io.LimitReader(compressed, poolLogCacheMaxBytes))
	if errDecode := decoder.Decode(&snapshot); errDecode != nil {
		return fmt.Errorf("decode pool log cache: %w", errDecode)
	}
	var trailing any
	if errTrailing := decoder.Decode(&trailing); errTrailing != io.EOF {
		if errTrailing == nil {
			return errors.New("decode pool log cache: trailing JSON value")
		}
		return fmt.Errorf("decode pool log cache trailing data: %w", errTrailing)
	}
	if snapshot.Version != poolLogCacheVersion {
		return fmt.Errorf("unsupported pool log cache version %d", snapshot.Version)
	}
	if errValidate := validatePoolLogCacheSnapshot(snapshot, time.Now().UTC(), c.maxEntries); errValidate != nil {
		return fmt.Errorf("validate pool log cache: %w", errValidate)
	}

	c.items = append([]poolSourceLog(nil), snapshot.Items...)
	c.afterID = snapshot.AfterID
	if snapshot.UpdatedAt > 0 {
		c.updatedAt = time.Unix(snapshot.UpdatedAt, 0).UTC()
	}
	if snapshot.LastSuccess > 0 {
		c.lastSuccess = time.Unix(snapshot.LastSuccess, 0).UTC()
	}
	if snapshot.CoverageFrom > 0 && snapshot.CoverageThrough >= snapshot.CoverageFrom {
		c.coverageFrom = time.Unix(snapshot.CoverageFrom, 0).UTC()
		c.coverageThrough = time.Unix(snapshot.CoverageThrough, 0).UTC()
	}
	c.rebuildIndexesLocked()
	c.dirty = false
	c.revision = 0
	return nil
}

func validatePoolLogCacheSnapshot(snapshot poolLogCacheSnapshot, now time.Time, maxEntries int) error {
	if maxEntries <= 0 {
		maxEntries = poolLogCacheMaxEntries
	}
	if len(snapshot.Items) > maxEntries {
		return fmt.Errorf("item count %d exceeds limit %d", len(snapshot.Items), maxEntries)
	}
	if snapshot.AfterID < 0 || snapshot.AfterID > poolLogCacheMaxSourceID {
		return errors.New("after_id is outside the supported range")
	}

	futureLimit := now.UTC().Add(poolLogCacheFutureSkew).Unix()
	validateTimestamp := func(name string, value int64) error {
		if value < 0 {
			return fmt.Errorf("%s is negative", name)
		}
		if value > futureLimit {
			return fmt.Errorf("%s is unreasonably far in the future", name)
		}
		return nil
	}
	if errUpdated := validateTimestamp("updated_at", snapshot.UpdatedAt); errUpdated != nil {
		return errUpdated
	}
	if errSuccess := validateTimestamp("last_success", snapshot.LastSuccess); errSuccess != nil {
		return errSuccess
	}
	if errFrom := validateTimestamp("coverage_from", snapshot.CoverageFrom); errFrom != nil {
		return errFrom
	}
	if errThrough := validateTimestamp("coverage_through", snapshot.CoverageThrough); errThrough != nil {
		return errThrough
	}

	coveragePresent := snapshot.CoverageFrom != 0 || snapshot.CoverageThrough != 0
	if coveragePresent {
		if snapshot.CoverageFrom == 0 || snapshot.CoverageThrough == 0 || snapshot.CoverageThrough < snapshot.CoverageFrom {
			return errors.New("coverage bounds are incomplete or reversed")
		}
		if snapshot.LastSuccess == 0 || snapshot.CoverageThrough > snapshot.LastSuccess+int64(poolLogCacheFutureSkew/time.Second) {
			return errors.New("coverage extends beyond the last successful source read")
		}
		if len(snapshot.Items) == 0 {
			return errors.New("an empty cache cannot claim complete coverage")
		}
		if len(snapshot.Items) >= maxEntries {
			return errors.New("a retention-limited cache cannot claim complete coverage")
		}
	}

	seenSourceIDs := make(map[int64]struct{}, len(snapshot.Items))
	seenRequestIDs := make(map[string]struct{}, len(snapshot.Items))
	var previousSourceID int64
	var maximumSourceID int64
	itemInsideCoverage := false
	for index, item := range snapshot.Items {
		sanitized, ok := sanitizePoolSourceLog(item)
		if !ok || sanitized != item {
			return fmt.Errorf("item %d is not a canonical safe source record", index)
		}
		if item.SourceID > poolLogCacheMaxSourceID {
			return fmt.Errorf("item %d source_id is outside the supported range", index)
		}
		if index > 0 && item.SourceID <= previousSourceID {
			return errors.New("items are not in strictly increasing source_id order")
		}
		if _, duplicate := seenSourceIDs[item.SourceID]; duplicate {
			return errors.New("items contain a duplicate source_id")
		}
		if _, duplicate := seenRequestIDs[item.RequestID]; duplicate {
			return errors.New("items contain a duplicate primary request_id")
		}
		if item.CreatedAt > futureLimit {
			return fmt.Errorf("item %d timestamp is unreasonably far in the future", index)
		}
		if snapshot.UpdatedAt == 0 || item.CreatedAt > snapshot.UpdatedAt+int64(poolLogCacheFutureSkew/time.Second) {
			return fmt.Errorf("item %d timestamp is inconsistent with updated_at", index)
		}
		if coveragePresent && item.CreatedAt >= snapshot.CoverageFrom && item.CreatedAt <= snapshot.CoverageThrough {
			itemInsideCoverage = true
		}
		seenSourceIDs[item.SourceID] = struct{}{}
		seenRequestIDs[item.RequestID] = struct{}{}
		previousSourceID = item.SourceID
		maximumSourceID = item.SourceID
	}
	if len(snapshot.Items) == 0 {
		if snapshot.AfterID != 0 || snapshot.UpdatedAt != 0 {
			return errors.New("an empty cache cannot carry a cursor or update timestamp")
		}
	} else if snapshot.AfterID > maximumSourceID {
		return errors.New("after_id is ahead of every cached source record")
	}
	if coveragePresent && !itemInsideCoverage {
		return errors.New("coverage contains no cached source record")
	}
	return nil
}

func (c *poolLogCache) normalizeLocked() {
	bySourceID := make(map[int64]poolSourceLog, len(c.items))
	for _, item := range c.items {
		item, ok := sanitizePoolSourceLog(item)
		if !ok {
			continue
		}
		bySourceID[item.SourceID] = item
	}
	byRequestID := make(map[string]poolSourceLog, len(bySourceID))
	for _, item := range bySourceID {
		if previous, exists := byRequestID[item.RequestID]; !exists || item.SourceID > previous.SourceID {
			byRequestID[item.RequestID] = item
		}
	}
	c.items = c.items[:0]
	for _, item := range byRequestID {
		c.items = append(c.items, item)
	}
	sort.Slice(c.items, func(i, j int) bool { return c.items[i].SourceID < c.items[j].SourceID })
	if len(c.items) > c.maxEntries {
		c.items = append([]poolSourceLog(nil), c.items[len(c.items)-c.maxEntries:]...)
	}
	if len(c.items) >= c.maxEntries {
		c.coverageFrom = time.Time{}
		c.coverageThrough = time.Time{}
	}
	c.rebuildIndexesLocked()
}

func (c *poolLogCache) rebuildIndexesLocked() {
	c.bySourceID = make(map[int64]int, len(c.items))
	c.byRequestID = make(map[string]int, len(c.items))
	c.byUpstreamID = make(map[string][]int, len(c.items))
	for index := range c.items {
		item := c.items[index]
		c.bySourceID[item.SourceID] = index
		c.byRequestID[item.RequestID] = index
		if item.UpstreamID != "" {
			c.byUpstreamID[item.UpstreamID] = append(c.byUpstreamID[item.UpstreamID], index)
		}
	}
}

func (c *poolLogCache) add(items []poolSourceLog, now time.Time) int {
	if c == nil || len(items) == 0 {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	added := 0
	changed := false
	for _, raw := range items {
		item, ok := sanitizePoolSourceLog(raw)
		if !ok {
			continue
		}
		if index, exists := c.bySourceID[item.SourceID]; exists {
			if c.items[index] != item {
				c.items[index] = item
				changed = true
				c.dirty = true
				c.revision++
			}
			continue
		}
		c.items = append(c.items, item)
		c.bySourceID[item.SourceID] = len(c.items) - 1
		added++
		changed = true
		c.dirty = true
		c.revision++
	}
	if !changed {
		return 0
	}
	c.normalizeLocked()
	c.updatedAt = now.UTC()
	return added
}

func (c *poolLogCache) markSuccess(now time.Time, afterID int64) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	changed := false
	if afterID > c.afterID {
		c.afterID = afterID
		changed = true
	}
	now = now.UTC()
	if !now.Equal(c.lastSuccess) {
		c.lastSuccess = now
		changed = true
	}
	if changed {
		c.dirty = true
		c.revision++
	}
}

func (c *poolLogCache) cursor() int64 {
	if c == nil {
		return 0
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.afterID
}

func (c *poolLogCache) lookup(requestID string) []poolSourceLog {
	if c == nil {
		return nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if index, ok := c.byRequestID[requestID]; ok && index >= 0 && index < len(c.items) {
		return []poolSourceLog{c.items[index]}
	}
	indexes := c.byUpstreamID[requestID]
	result := make([]poolSourceLog, 0, len(indexes))
	for _, index := range indexes {
		if index >= 0 && index < len(c.items) {
			result = append(result, c.items[index])
		}
	}
	return result
}

func (c *poolLogCache) query(from, to time.Time, limit int) []poolSourceLog {
	if c == nil {
		return nil
	}
	if limit <= 0 || limit > c.maxEntries {
		limit = c.maxEntries
	}
	fromUnix := from.Unix()
	toUnix := to.Unix()
	c.mu.RLock()
	defer c.mu.RUnlock()
	result := make([]poolSourceLog, 0, len(c.items))
	for _, item := range c.items {
		if item.CreatedAt < fromUnix || item.CreatedAt > toUnix {
			continue
		}
		result = append(result, item)
	}
	sort.SliceStable(result, func(i, j int) bool {
		if result[i].CreatedAt != result[j].CreatedAt {
			return result[i].CreatedAt > result[j].CreatedAt
		}
		return result[i].SourceID > result[j].SourceID
	})
	if len(result) > limit {
		result = result[:limit]
	}
	return result
}

func (c *poolLogCache) covers(from, to time.Time) bool {
	if c == nil {
		return false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	// A full cache is conservatively treated as truncated. This avoids claiming
	// complete time coverage when retention may have cut through a busy second.
	if len(c.items) >= c.maxEntries || c.coverageFrom.IsZero() || c.coverageThrough.IsZero() {
		return false
	}
	return !from.UTC().Before(c.coverageFrom) && !to.UTC().After(c.coverageThrough)
}

// markCoverage records a range known to have been fetched completely. Exact
// lookups never call this method because isolated records cannot prove range
// completeness.
func (c *poolLogCache) markCoverage(from, through time.Time) {
	if c == nil {
		return
	}
	from = from.UTC()
	through = through.UTC()
	if from.IsZero() || through.IsZero() || through.Before(from) {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.items) == 0 || len(c.items) >= c.maxEntries {
		return
	}
	containsRecord := false
	fromUnix := from.Unix()
	throughUnix := through.Unix()
	for _, item := range c.items {
		if item.CreatedAt >= fromUnix && item.CreatedAt <= throughUnix {
			containsRecord = true
			break
		}
	}
	if !containsRecord {
		return
	}

	changed := false
	switch {
	case c.coverageFrom.IsZero() || c.coverageThrough.IsZero():
		c.coverageFrom = from
		c.coverageThrough = through
		changed = true
	case !through.Before(c.coverageFrom) && !from.After(c.coverageThrough.Add(poolLogPollInterval)):
		if from.Before(c.coverageFrom) {
			c.coverageFrom = from
			changed = true
		}
		if through.After(c.coverageThrough) {
			c.coverageThrough = through
			changed = true
		}
	case through.After(c.coverageThrough):
		// Prefer a newer complete window over a disjoint historical query.
		c.coverageFrom = from
		c.coverageThrough = through
		changed = true
	}
	if changed {
		c.dirty = true
		c.revision++
	}
}

func (c *poolLogCache) extendCoverage(through time.Time) {
	if c == nil {
		return
	}
	through = through.UTC()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.coverageFrom.IsZero() || c.coverageThrough.IsZero() || !through.After(c.coverageThrough) {
		return
	}
	c.coverageThrough = through
	c.dirty = true
	c.revision++
}

func (c *poolLogCache) stats() (entries int, afterID int64, lastSuccess time.Time) {
	if c == nil {
		return 0, 0, time.Time{}
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.items), c.afterID, c.lastSuccess
}

func (c *poolLogCache) persist() error {
	if c == nil || c.path == "" {
		return nil
	}
	c.mu.RLock()
	if !c.dirty {
		c.mu.RUnlock()
		return nil
	}
	revision := c.revision
	unixOrZero := func(value time.Time) int64 {
		if value.IsZero() {
			return 0
		}
		return value.Unix()
	}
	snapshot := poolLogCacheSnapshot{
		Version:         poolLogCacheVersion,
		AfterID:         c.afterID,
		UpdatedAt:       unixOrZero(c.updatedAt),
		LastSuccess:     unixOrZero(c.lastSuccess),
		CoverageFrom:    unixOrZero(c.coverageFrom),
		CoverageThrough: unixOrZero(c.coverageThrough),
		Items:           append([]poolSourceLog(nil), c.items...),
	}
	c.mu.RUnlock()

	directory := filepath.Dir(c.path)
	if errMkdir := os.MkdirAll(directory, 0o700); errMkdir != nil {
		return fmt.Errorf("create pool log cache directory: %w", errMkdir)
	}
	temporary, errCreate := os.CreateTemp(directory, ".pool-log-cache-*.json.gz")
	if errCreate != nil {
		return fmt.Errorf("create pool log cache: %w", errCreate)
	}
	temporaryName := temporary.Name()
	removeTemporary := true
	defer func() {
		if removeTemporary {
			if errRemove := os.Remove(temporaryName); errRemove != nil && !os.IsNotExist(errRemove) {
				log.WithError(errRemove).Warn("failed to remove temporary New API pool log cache")
			}
		}
	}()

	compressed := gzip.NewWriter(temporary)
	encoder := json.NewEncoder(compressed)
	if errEncode := encoder.Encode(snapshot); errEncode != nil {
		_ = compressed.Close()
		_ = temporary.Close()
		return fmt.Errorf("encode pool log cache: %w", errEncode)
	}
	if errCloseGzip := compressed.Close(); errCloseGzip != nil {
		_ = temporary.Close()
		return fmt.Errorf("compress pool log cache: %w", errCloseGzip)
	}
	if errSync := temporary.Sync(); errSync != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync pool log cache: %w", errSync)
	}
	if errClose := temporary.Close(); errClose != nil {
		return fmt.Errorf("close pool log cache: %w", errClose)
	}
	if errChmod := os.Chmod(temporaryName, 0o600); errChmod != nil {
		return fmt.Errorf("secure pool log cache: %w", errChmod)
	}
	if errRename := os.Rename(temporaryName, c.path); errRename != nil {
		return fmt.Errorf("replace pool log cache: %w", errRename)
	}
	removeTemporary = false

	c.mu.Lock()
	if c.revision == revision {
		c.dirty = false
	}
	c.mu.Unlock()
	return nil
}
