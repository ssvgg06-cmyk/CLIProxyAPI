package management

import (
	"context"
	"sort"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

// poolRPMAtMinute interpolates the historical traffic curve used by the quota
// cards. It no longer creates request logs; New API is their only source.
func poolRPMAtMinute(minute int64) float64 {
	offset := ((minute % 1440) + 1440) % 1440
	hour := int(offset / 60)
	fraction := float64(offset%60) / 60.0
	next := (hour + 1) % 24
	return poolHourlyRPM[hour]*(1-fraction) + poolHourlyRPM[next]*fraction
}

func poolRPMAt(t time.Time) float64 {
	return poolRPMAtMinute(t.UTC().Unix() / 60)
}

func poolMeanRPM() float64 {
	total := 0.0
	for _, value := range poolHourlyRPM {
		total += value
	}
	return total / float64(len(poolHourlyRPM))
}

// normalizeLocked applies defaults and clamps a filter to the retention
// window. Despite the historical name, it mutates only the caller-owned value.
func (f *poolLogFilter) normalizeLocked(now time.Time) {
	if f.To.IsZero() || f.To.After(now) {
		f.To = now
	}
	if f.From.IsZero() {
		window := poolDefaultTailWindow
		if f.RequestID != "" {
			window = poolHistoryWindow
		}
		f.From = f.To.Add(-window)
	}
	earliest := now.Add(-poolHistoryWindow)
	if f.From.Before(earliest) {
		f.From = earliest
	}
	if f.From.After(f.To) {
		f.From = f.To
	}
	if f.Limit <= 0 {
		f.Limit = poolDefaultLogLimit
	}
	if f.Limit > poolMaxLogLimit {
		f.Limit = poolMaxLogLimit
	}
	f.Level = strings.ToUpper(strings.TrimSpace(f.Level))
	f.Query = strings.ToLower(strings.TrimSpace(f.Query))
}

func (f *poolLogFilter) accepts(entry poolLogEntry) bool {
	if entry.Timestamp < f.From.Unix() || entry.Timestamp > f.To.Unix() {
		return false
	}
	if f.Level != "" && entry.Level != f.Level {
		return false
	}
	if f.RequestID != "" && entry.RequestID != f.RequestID && entry.UpstreamID != f.RequestID {
		return false
	}
	return entry.matches(f.Query)
}

func poolLogOutcome(item poolSourceLog) (level, message string) {
	if item.Type == 2 && item.Status >= 200 && item.Status < 400 {
		return "INFO", "request completed"
	}
	switch item.Status {
	case 408, 504:
		return "ERROR", "upstream request timed out"
	case 429:
		return "WARN", "rate limit reached"
	case 529:
		return "ERROR", "upstream overloaded"
	default:
		return "ERROR", "upstream request failed"
	}
}

func (s *poolSimulator) sourceLogEntry(item poolSourceLog) poolLogEntry {
	account, mapped := s.mapRequestAccount(time.Unix(item.CreatedAt, 0).UTC(), item.RequestID)
	return poolSourceLogEntry(item, account, mapped)
}

func poolSourceLogEntry(item poolSourceLog, account poolLogAccount, mapped bool) poolLogEntry {
	level, message := poolLogOutcome(item)
	entry := poolLogEntry{
		Timestamp:     item.CreatedAt,
		Level:         level,
		Message:       message,
		Source:        "newapi",
		MappingStatus: "unmapped",
		LogType:       item.Type,
		RequestID:     item.RequestID,
		UpstreamID:    item.UpstreamID,
		Model:         item.Model,
		Status:        item.Status,
		LatencyMS:     item.LatencyMS,
	}
	if mapped {
		entry.MappingStatus = "mapped"
		entry.AuthIndex = account.AuthIndex
		entry.Account = account.Name
		entry.Email = account.Email
	}
	return entry
}

// sourceLogEntries materializes first-observed request mappings as one atomic
// pool-state update. It deliberately does not call advanceLocked or touch quota
// and request counters, so reading logs cannot evolve the displayed pool.
func (s *poolSimulator) sourceLogEntries(items []poolSourceLog) []poolLogEntry {
	entries := make([]poolLogEntry, 0, len(items))
	s.mu.Lock()
	changed := false
	projectedRosters := make(map[int64][]poolLogAccount)
	latestRequestAt := time.Time{}
	for _, item := range items {
		requestAt := time.Unix(item.CreatedAt, 0).UTC()
		if requestAt.After(latestRequestAt) {
			latestRequestAt = requestAt
		}
		var account poolLogAccount
		var mapped, created bool
		if mapping, exists := s.state.RequestMappings[item.RequestID]; exists {
			account, mapped = s.resolveRequestMappingLocked(mapping), true
		} else {
			epoch := requestAt.Unix() / poolEpochSeconds
			roster, cached := projectedRosters[epoch]
			if !cached {
				var projected bool
				roster, projected = s.mappingRosterAtTimeLocked(requestAt)
				if projected {
					projectedRosters[epoch] = roster
				}
			}
			account, mapped, created = s.pinRequestAccountLocked(requestAt, item.RequestID, roster)
		}
		changed = changed || created
		entries = append(entries, poolSourceLogEntry(item, account, mapped))
	}
	if changed {
		s.trimRequestMappingsLocked(latestRequestAt)
	}
	if s.mappingDirty {
		if errPersist := s.persistLocked(); errPersist != nil {
			// Keep the in-memory pins even when persistence is temporarily
			// unavailable; the next mapping batch will retry the atomic write.
			log.WithError(errPersist).Warn("failed to persist request-to-account mappings")
		}
	}
	s.mu.Unlock()
	return entries
}

func (s *poolSimulator) lifecycleLogs(filter poolLogFilter) []poolLogEntry {
	s.mu.Lock()
	events := append([]poolLogEntry(nil), s.state.Events...)
	s.mu.Unlock()
	result := make([]poolLogEntry, 0, len(events))
	for _, event := range events {
		if event.Source == "" {
			event.Source = "cpa"
		}
		if filter.accepts(event) {
			result = append(result, event)
		}
	}
	return result
}

// queryLogsWithContext joins real, scrubbed New API request records with local
// credential lifecycle events. It never advances or persists pool quota state.
func (s *poolSimulator) queryLogsWithContext(ctx context.Context, now time.Time, filter poolLogFilter) ([]poolLogEntry, int, int64, bool, error) {
	now = now.UTC()
	filter.normalizeLocked(now)
	service := poolLogServiceFor(s)

	var (
		sourceItems    []poolSourceLog
		sourceTruncate bool
		sourceErr      error
	)
	if filter.RequestID != "" {
		sourceItems, sourceErr = service.lookup(ctx, filter.RequestID)
	} else {
		// Scan the bounded source window before applying the response limit so
		// line-count reports this query's matched total rather than page length.
		sourceItems, sourceTruncate, sourceErr = service.search(ctx, filter.From, filter.To, poolMaxLogLimit)
	}

	entries := make([]poolLogEntry, 0, len(sourceItems)+32)
	for _, entry := range s.sourceLogEntries(sourceItems) {
		if filter.accepts(entry) {
			entries = append(entries, entry)
		}
	}
	entries = append(entries, s.lifecycleLogs(filter)...)
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].Timestamp != entries[j].Timestamp {
			return entries[i].Timestamp < entries[j].Timestamp
		}
		if entries[i].RequestID != entries[j].RequestID {
			return entries[i].RequestID < entries[j].RequestID
		}
		return entries[i].Message < entries[j].Message
	})
	total := len(entries)
	truncated := sourceTruncate
	if sourceErr != nil && filter.RequestID == "" {
		truncated = true
	}
	if len(entries) > filter.Limit {
		entries = append([]poolLogEntry(nil), entries[len(entries)-filter.Limit:]...)
		truncated = true
	}

	latest := filter.To.Unix()
	if len(entries) > 0 && entries[len(entries)-1].Timestamp > 0 {
		latest = entries[len(entries)-1].Timestamp
	}
	return entries, total, latest, truncated, sourceErr
}

// queryLogs keeps the existing internal call shape. HTTP handlers use the
// context-aware form so an unavailable exact lookup can return 503 instead of
// pretending the identifier does not exist.
func (s *poolSimulator) queryLogs(now time.Time, filter poolLogFilter) ([]poolLogEntry, int64, bool) {
	entries, _, latest, truncated, _ := s.queryLogsWithContext(context.Background(), now, filter)
	return entries, latest, truncated
}

func (s *poolSimulator) findRequestEntryWithContext(ctx context.Context, now time.Time, requestID string) (poolLogEntry, bool, error) {
	if !validPoolRequestID(requestID) {
		return poolLogEntry{}, false, nil
	}
	entries, _, _, _, errQuery := s.queryLogsWithContext(ctx, now, poolLogFilter{RequestID: requestID, Limit: 100})
	for index := len(entries) - 1; index >= 0; index-- {
		if entries[index].RequestID == requestID || entries[index].UpstreamID == requestID {
			return entries[index], true, errQuery
		}
	}
	return poolLogEntry{}, false, errQuery
}

func (s *poolSimulator) findRequestEntry(now time.Time, requestID string) (poolLogEntry, bool) {
	entry, found, _ := s.findRequestEntryWithContext(context.Background(), now, requestID)
	return entry, found
}

func (s *poolSimulator) recentErrorEntries(now time.Time, window time.Duration, limit int) []poolLogEntry {
	entries, _, _ := s.queryLogs(now, poolLogFilter{
		From: now.UTC().Add(-window),
		To:   now.UTC(),
		// Filter the broad source page before applying the small error-file cap;
		// otherwise high-volume successful requests can evict every type-5 row.
		Limit: poolMaxLogLimit,
	})
	filtered := make([]poolLogEntry, 0, len(entries))
	for _, entry := range entries {
		if entry.RequestID != "" && entry.LogType == 5 {
			filtered = append(filtered, entry)
		}
	}
	sort.SliceStable(filtered, func(i, j int) bool { return filtered[i].Timestamp > filtered[j].Timestamp })
	if len(filtered) > limit {
		filtered = filtered[:limit]
	}
	return filtered
}

func (s *poolSimulator) logLinesWithContext(ctx context.Context, now time.Time, filter poolLogFilter) ([]string, int, int64, bool, error) {
	entries, total, latest, truncated, errQuery := s.queryLogsWithContext(ctx, now, filter)
	lines := make([]string, 0, len(entries))
	for _, entry := range entries {
		lines = append(lines, entry.Line())
	}
	return lines, total, latest, truncated, errQuery
}

func (s *poolSimulator) logLines(now time.Time, filter poolLogFilter) ([]string, int, int64, bool) {
	lines, total, latest, truncated, _ := s.logLinesWithContext(context.Background(), now, filter)
	return lines, total, latest, truncated
}

func (s *poolSimulator) logSourceMetadata(now time.Time) poolLogSourceMetadata {
	service := poolLogServiceFor(s)
	if service == nil {
		return poolLogSourceMetadata{Kind: "newapi", Name: "new-api", Status: "unavailable", Stale: true}
	}
	return service.metadata(now)
}
