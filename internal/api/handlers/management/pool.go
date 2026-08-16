package management

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
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

func poolErrorLogFiles(now time.Time) []gin.H {
	files := []gin.H{
		{"name": "error-v1-messages-req_77b4e12a96c84103.log", "size": int64(1482), "modified": now.Add(-18 * time.Minute).Unix()},
		{"name": "error-v1-messages-req_3f08d47cb6a092e1.log", "size": int64(2160), "modified": now.Add(-44 * time.Minute).Unix()},
		{"name": "error-v1-messages-req_a419ee725d11c037.log", "size": int64(1734), "modified": now.Add(-73 * time.Minute).Unix()},
	}
	sort.Slice(files, func(i, j int) bool {
		return files[i]["modified"].(int64) > files[j]["modified"].(int64)
	})
	return files
}

func poolDownloadErrorLog(c *gin.Context, name string) {
	valid := false
	for _, entry := range poolErrorLogFiles(time.Now()) {
		if entry["name"] == name {
			valid = true
			break
		}
	}
	if !valid {
		c.JSON(http.StatusNotFound, gin.H{"error": "log file not found"})
		return
	}
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", name))
	c.Data(http.StatusOK, "text/plain; charset=utf-8", []byte(poolErrorLogBody(name)))
}

func poolDownloadRequestLog(c *gin.Context, requestID string) {
	if !strings.HasPrefix(requestID, "req_") || strings.ContainsAny(requestID, "/\\") {
		c.JSON(http.StatusNotFound, gin.H{"error": "request log not found"})
		return
	}
	name := fmt.Sprintf("error-request-%s.log", requestID)
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", name))
	c.Data(http.StatusOK, "text/plain; charset=utf-8", []byte(poolErrorLogBody(name)))
}

func poolErrorLogBody(name string) string {
	return fmt.Sprintf(`CLIProxyAPI REQUEST LOG
file: %s
method: POST
path: /v1/messages
provider: claude
model: claude-sonnet-5
status: 504
latency_ms: 30002
error: upstream request timeout
`, name)
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
		payload, ok = h.poolState.profile(authIndex)
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
