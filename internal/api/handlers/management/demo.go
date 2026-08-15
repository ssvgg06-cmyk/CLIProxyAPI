package management

import (
	"fmt"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

const demoModeEnvironment = "CPA_DEMO_MODE"

func demoModeEnabled() bool {
	raw := strings.TrimSpace(os.Getenv(demoModeEnvironment))
	enabled, err := strconv.ParseBool(raw)
	return err == nil && enabled
}

func demoRequestAllowed(method, path string) bool {
	switch method {
	case http.MethodHead, http.MethodOptions:
		return true
	case http.MethodGet:
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
	default:
		return false
	}
}

func demoAuthFiles(now time.Time) []gin.H {
	providers := []struct {
		name    string
		label   string
		account string
	}{
		{name: "codex", label: "OpenAI Codex", account: "ChatGPT Plus"},
		{name: "gemini-cli", label: "Gemini CLI", account: "Google AI Pro"},
		{name: "claude", label: "Claude Code", account: "Claude Pro"},
		{name: "antigravity", label: "Antigravity", account: "Workspace"},
	}

	files := make([]gin.H, 0, 36)
	for i := 1; i <= 36; i++ {
		provider := providers[(i-1)%len(providers)]
		status := "active"
		statusMessage := "Demo credential is healthy"
		disabled := false
		unavailable := false
		failed := int64(i % 4)
		if i%11 == 0 {
			status = "disabled"
			statusMessage = "Disabled for demo maintenance"
			disabled = true
		} else if i%7 == 0 {
			status = "error"
			statusMessage = "Demo quota temporarily unavailable"
			unavailable = true
			failed += 5
		} else if i%5 == 0 {
			status = "refreshing"
			statusMessage = "Refreshing demo credential"
		}

		updated := now.UTC().Add(-time.Duration(i*13) * time.Minute)
		entry := gin.H{
			"id":              fmt.Sprintf("demo-%s-%02d", provider.name, i),
			"auth_index":      fmt.Sprintf("demo-%s-%02d", provider.name, i),
			"name":            fmt.Sprintf("demo-%s-%02d.json", provider.name, i),
			"type":            provider.name,
			"provider":        provider.name,
			"label":           provider.label,
			"account_type":    provider.account,
			"account":         fmt.Sprintf("DEMO-%04d", 1000+i),
			"email":           fmt.Sprintf("demo.%02d@sample.test", i),
			"status":          status,
			"status_message":  statusMessage,
			"disabled":        disabled,
			"unavailable":     unavailable,
			"runtime_only":    false,
			"source":          "demo",
			"size":            int64(1800 + i*37),
			"priority":        (i - 1) % 5,
			"note":            "DEMO DATA — contains no usable credentials",
			"success":         int64(180 + i*23),
			"failed":          failed,
			"created_at":      updated.Add(-time.Duration(10+i) * 24 * time.Hour),
			"updated_at":      updated,
			"modtime":         updated,
			"last_refresh":    updated.Add(-7 * time.Minute),
			"recent_requests": demoRecentRequests(now, i),
		}
		if provider.name == "codex" {
			plans := []string{"plus", "team", "pro"}
			entry["id_token"] = gin.H{
				"chatgpt_account_id": fmt.Sprintf("demo-account-%04d", i),
				"plan_type":          plans[i%len(plans)],
			}
		}
		if provider.name == "gemini-cli" || provider.name == "antigravity" {
			entry["project_id"] = fmt.Sprintf("demo-project-%03d", i)
		}
		files = append(files, entry)
	}
	return files
}

func demoRecentRequests(now time.Time, seed int) []gin.H {
	buckets := make([]gin.H, 0, 20)
	for i := 19; i >= 0; i-- {
		buckets = append(buckets, gin.H{
			"time":    now.UTC().Add(-time.Duration(i*10) * time.Minute).Format(time.RFC3339),
			"success": int64(3 + (seed+i*3)%18),
			"failed":  int64((seed + i) % 3),
		})
	}
	return buckets
}

func demoModelsForAuth(name string) []gin.H {
	lower := strings.ToLower(name)
	models := []string{"gpt-5.2-codex", "gpt-5.1-codex-mini"}
	ownedBy := "openai"
	if strings.Contains(lower, "gemini") || strings.Contains(lower, "antigravity") {
		models = []string{"gemini-3-pro-preview", "gemini-3-flash-preview"}
		ownedBy = "google"
	} else if strings.Contains(lower, "claude") {
		models = []string{"claude-opus-4-6", "claude-sonnet-4-6"}
		ownedBy = "anthropic"
	}
	result := make([]gin.H, 0, len(models))
	for _, model := range models {
		result = append(result, gin.H{"id": model, "display_name": model, "owned_by": ownedBy})
	}
	return result
}

func demoLogLines(now time.Time, after int64, limit int) ([]string, int, int64) {
	levels := []string{"INFO", "INFO", "INFO", "DEBUG", "WARN"}
	providers := []string{"codex", "gemini-cli", "claude", "antigravity"}
	lines := make([]string, 0, 120)
	latest := int64(0)
	for i := 119; i >= 0; i-- {
		ts := now.Add(-time.Duration(i) * 45 * time.Second)
		unix := ts.Unix()
		if unix > latest {
			latest = unix
		}
		if after > 0 && unix <= after {
			continue
		}
		level := levels[i%len(levels)]
		provider := providers[i%len(providers)]
		status := 200
		latency := 280 + (i*37)%2100
		message := fmt.Sprintf("request completed provider=%s model=%s status=%d latency_ms=%d request_id=demo-%06d", provider, demoModelForProvider(provider), status, latency, 900000+i)
		if i%17 == 0 {
			level = "WARN"
			message = fmt.Sprintf("quota threshold reached provider=%s remaining=%d%% request_id=demo-%06d", provider, 8+i%17, 900000+i)
		}
		if i%29 == 0 {
			level = "ERROR"
			message = fmt.Sprintf("upstream demo timeout provider=%s status=504 retry=1 request_id=demo-%06d", provider, 900000+i)
		}
		lines = append(lines, fmt.Sprintf("[%s] [%s] %s", ts.Format("2006-01-02 15:04:05"), level, message))
	}
	total := len(lines)
	if limit > 0 && len(lines) > limit {
		lines = lines[len(lines)-limit:]
	}
	return lines, total, latest
}

func demoModelForProvider(provider string) string {
	switch provider {
	case "gemini-cli", "antigravity":
		return "gemini-3-pro-preview"
	case "claude":
		return "claude-sonnet-4-6"
	default:
		return "gpt-5.2-codex"
	}
}

func demoErrorLogFiles(now time.Time) []gin.H {
	files := []gin.H{
		{"name": "error-v1-responses-demo-900087.log", "size": int64(1482), "modified": now.Add(-18 * time.Minute).Unix()},
		{"name": "error-v1-chat-completions-demo-900058.log", "size": int64(2160), "modified": now.Add(-44 * time.Minute).Unix()},
		{"name": "error-v1-responses-demo-900029.log", "size": int64(1734), "modified": now.Add(-73 * time.Minute).Unix()},
	}
	sort.Slice(files, func(i, j int) bool {
		return files[i]["modified"].(int64) > files[j]["modified"].(int64)
	})
	return files
}

func demoDownloadErrorLog(c *gin.Context, name string) {
	valid := false
	for _, entry := range demoErrorLogFiles(time.Now()) {
		if entry["name"] == name {
			valid = true
			break
		}
	}
	if !valid {
		c.JSON(http.StatusNotFound, gin.H{"error": "demo log file not found"})
		return
	}
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", name))
	c.Data(http.StatusOK, "text/plain; charset=utf-8", []byte(demoErrorLogBody(name)))
}

func demoDownloadRequestLog(c *gin.Context, requestID string) {
	if !strings.HasPrefix(requestID, "demo-") {
		c.JSON(http.StatusNotFound, gin.H{"error": "demo request log not found"})
		return
	}
	name := fmt.Sprintf("error-request-%s.log", requestID)
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", name))
	c.Data(http.StatusOK, "text/plain; charset=utf-8", []byte(demoErrorLogBody(name)))
}

func demoErrorLogBody(name string) string {
	return fmt.Sprintf(`CPA DEMO REQUEST LOG
file: %s
notice: This is synthetic demonstration data. It contains no tokens or credentials.
method: POST
path: /v1/responses
provider: codex
model: gpt-5.2-codex
status: 504
latency_ms: 30002
error: synthetic upstream timeout used for UI demonstration
`, name)
}
