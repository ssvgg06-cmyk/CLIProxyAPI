package management

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	poolModeEnvironment  = "CPA_POOL_MODE"
	poolStateEnvironment = "CPA_POOL_STATE_PATH"
	defaultPoolStatePath = "/pool/state/pool-state.json"
)

func poolModeEnabled() bool {
	raw := strings.TrimSpace(os.Getenv(poolModeEnvironment))
	enabled, err := strconv.ParseBool(raw)
	return err == nil && enabled
}

func poolStatePath() string {
	if value := strings.TrimSpace(os.Getenv(poolStateEnvironment)); value != "" {
		return filepath.Clean(value)
	}
	return defaultPoolStatePath
}

func poolRequestAllowed(method, path string) bool {
	if method == http.MethodHead || method == http.MethodOptions {
		return true
	}
	if method == http.MethodPost {
		return strings.HasSuffix(path, "/api-call")
	}
	if method != http.MethodGet {
		return false
	}
	for _, blocked := range []string{
		"/anthropic-auth-url",
		"/codex-auth-url",
		"/gemini-cli-auth-url",
		"/antigravity-auth-url",
		"/kimi-auth-url",
		"/xai-auth-url",
		"/get-auth-status",
		"/auth-files/download",
	} {
		if strings.HasSuffix(path, blocked) {
			return false
		}
	}
	return true
}

func poolModelsForAuth(_ string) []gin.H {
	result := make([]gin.H, 0, len(poolModelIDs))
	for _, model := range poolModelIDs {
		result = append(result, gin.H{"id": model, "display_name": model, "owned_by": "anthropic"})
	}
	return result
}

// parsePoolTime accepts either a Unix timestamp in seconds or an RFC3339 instant.
func parsePoolTime(raw string) (time.Time, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return time.Time{}, nil
	}
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil {
		if seconds <= 0 {
			return time.Time{}, fmt.Errorf("must be a positive Unix timestamp")
		}
		return time.Unix(seconds, 0).UTC(), nil
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("must be a Unix timestamp or an RFC3339 instant")
	}
	return parsed.UTC(), nil
}

// poolLogFilterFromQuery builds a log filter from the management query string.
func poolLogFilterFromQuery(c *gin.Context, limit int) (poolLogFilter, error) {
	filter := poolLogFilter{
		Level:     c.Query("level"),
		RequestID: c.Query("request_id"),
		Query:     c.Query("q"),
		Limit:     limit,
	}
	from, errFrom := parsePoolTime(c.Query("from"))
	if errFrom != nil {
		return filter, fmt.Errorf("invalid from: %v", errFrom)
	}
	to, errTo := parsePoolTime(c.Query("to"))
	if errTo != nil {
		return filter, fmt.Errorf("invalid to: %v", errTo)
	}
	filter.From = from
	filter.To = to
	// "after" keeps the incremental polling contract: strictly newer than the cutoff.
	if cutoff := parseCutoff(c.Query("after")); cutoff > 0 && filter.From.IsZero() {
		filter.From = time.Unix(cutoff+1, 0).UTC()
	}
	switch strings.ToUpper(strings.TrimSpace(filter.Level)) {
	case "", "INFO", "WARN", "ERROR", "DEBUG":
	default:
		return filter, fmt.Errorf("invalid level: must be one of INFO, WARN, ERROR, DEBUG")
	}
	return filter, nil
}

// poolLogEntriesPayload renders structured log records for API consumers.
func poolLogEntriesPayload(entries []poolLogEntry) []gin.H {
	payload := make([]gin.H, 0, len(entries))
	for _, entry := range entries {
		item := gin.H{
			"timestamp": entry.Timestamp,
			"time":      time.Unix(entry.Timestamp, 0).Format(time.RFC3339),
			"time_utc":  time.Unix(entry.Timestamp, 0).UTC().Format(time.RFC3339),
			"level":     entry.Level,
			"message":   entry.Message,
			"line":      entry.Line(),
			"source":    entry.Source,
		}
		if entry.MappingStatus != "" {
			item["mapping_status"] = entry.MappingStatus
		}
		if entry.LogType != 0 {
			item["log_type"] = entry.LogType
		}
		if entry.RequestID != "" {
			item["request_id"] = entry.RequestID
			item["upstream_request_id"] = entry.UpstreamID
			item["auth_index"] = entry.AuthIndex
			item["account"] = entry.Account
			item["email"] = entry.Email
			item["model"] = entry.Model
			item["status"] = entry.Status
			item["latency_ms"] = entry.LatencyMS
		}
		payload = append(payload, item)
	}
	return payload
}

// poolTimezonePayload reports the wall clock used by rendered log lines so
// callers never have to infer it. Request identifiers remain opaque.
func poolTimezonePayload(now time.Time) gin.H {
	name, offset := now.Zone()
	return gin.H{
		"timezone":           name,
		"utc_offset_seconds": offset,
		"utc_offset":         now.Format("-07:00"),
		"request_id_format":  "opaque",
	}
}

// poolLogFileName creates a route-safe filename without embedding the opaque
// upstream identifier in a URL path or response header.
func poolLogFileName(prefix string, entry poolLogEntry) string {
	digest := sha256.Sum256([]byte(entry.RequestID))
	return fmt.Sprintf("%s-%s-%x.log",
		prefix, time.Unix(entry.Timestamp, 0).Format("2006-01-02T150405"), digest[:10])
}

// poolErrorLogName renders the canonical name for a failed request log.
func poolErrorLogName(entry poolLogEntry) string {
	return poolLogFileName("error-v1-messages", entry)
}

func poolRequestLogName(entry poolLogEntry) string {
	return poolLogFileName("request-v1-messages", entry)
}

// poolErrorLogFiles lists recent failed requests as downloadable log files.
func (h *Handler) poolErrorLogFiles(now time.Time) []gin.H {
	entries := h.poolState.recentErrorEntries(now, 24*time.Hour, 200)
	files := make([]gin.H, 0, len(entries))
	for _, entry := range entries {
		files = append(files, gin.H{
			"name":     poolErrorLogName(entry),
			"size":     int64(len(poolErrorLogBody(entry))),
			"modified": entry.Timestamp,
		})
	}
	return files
}

func (h *Handler) poolDownloadErrorLog(c *gin.Context, name string) {
	name = strings.TrimSpace(name)
	if name == "" || strings.ContainsAny(name, "/\\") {
		c.JSON(http.StatusNotFound, gin.H{"error": "log file not found"})
		return
	}
	var matched poolLogEntry
	found := false
	for _, entry := range h.poolState.recentErrorEntries(time.Now(), 24*time.Hour, 200) {
		if entry.LogType == 5 && name == poolErrorLogName(entry) {
			matched = entry
			found = true
			break
		}
	}
	if !found {
		c.JSON(http.StatusNotFound, gin.H{"error": "log file not found"})
		return
	}
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%q", poolErrorLogName(matched)))
	c.Data(http.StatusOK, "text/plain; charset=utf-8", []byte(poolErrorLogBody(matched)))
}

func (h *Handler) poolDownloadRequestLog(c *gin.Context, requestID string) {
	if !validPoolRequestID(requestID) {
		c.JSON(http.StatusNotFound, gin.H{"error": "request log not found"})
		return
	}
	entry, ok, errLookup := h.poolState.findRequestEntryWithContext(c.Request.Context(), time.Now(), requestID)
	if !ok {
		if errLookup != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"error":  "New API log source unavailable",
				"source": h.poolState.logSourceMetadata(time.Now()),
			})
			return
		}
		c.JSON(http.StatusNotFound, gin.H{"error": "request log not found"})
		return
	}
	name := poolRequestLogName(entry)
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name))
	c.Data(http.StatusOK, "text/plain; charset=utf-8", []byte(poolRequestLogBody(entry)))
}

// poolErrorLogBody renders the request log body for a single pool record.
func poolErrorLogBody(entry poolLogEntry) string {
	return poolLogBody(poolErrorLogName(entry), entry)
}

func poolRequestLogBody(entry poolLogEntry) string {
	return poolLogBody(poolRequestLogName(entry), entry)
}

func poolLogBody(name string, entry poolLogEntry) string {
	return fmt.Sprintf(`CLIProxyAPI REQUEST LOG
file: %s
timestamp: %s
request_id: %s
upstream_request_id: %s
source: %s
mapping_status: %s
log_type: %d
method: POST
path: /v1/messages
provider: claude
account: %s
email: %s
auth_index: %s
model: %s
status: %d
latency_ms: %d
result: %s
`,
		name,
		time.Unix(entry.Timestamp, 0).Format(time.RFC3339),
		entry.RequestID,
		entry.UpstreamID,
		entry.Source,
		entry.MappingStatus,
		entry.LogType,
		entry.Account,
		entry.Email,
		entry.AuthIndex,
		entry.Model,
		entry.Status,
		entry.LatencyMS,
		entry.Message,
	)
}

func (h *Handler) poolAPICall(c *gin.Context, body apiCallRequest) {
	method := strings.ToUpper(strings.TrimSpace(body.Method))
	if method != http.MethodGet {
		c.JSON(http.StatusForbidden, gin.H{"error": "request is not available"})
		return
	}
	authIndex := firstNonEmptyString(body.AuthIndexSnake, body.AuthIndexCamel, body.AuthIndexPascal)
	var payload gin.H
	var ok bool
	switch strings.TrimSpace(body.URL) {
	case "https://api.anthropic.com/api/oauth/usage":
		payload, ok = h.poolState.usage(time.Now(), authIndex)
	case "https://api.anthropic.com/api/oauth/profile":
		payload, ok = h.poolState.profile(time.Now(), authIndex)
	default:
		c.JSON(http.StatusForbidden, gin.H{"error": "request is not available"})
		return
	}
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "auth file not found"})
		return
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to encode response"})
		return
	}
	c.JSON(http.StatusOK, apiCallResponse{
		StatusCode: http.StatusOK,
		Header:     map[string][]string{"Content-Type": {"application/json"}},
		Body:       string(encoded),
	})
}
