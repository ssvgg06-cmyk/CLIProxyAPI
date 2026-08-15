package management

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

const poolModeEnvironment = "CPA_POOL_MODE"

var poolFirstNames = []string{
	"alex", "andrew", "benjamin", "charles", "daniel", "david", "ethan", "henry", "jack", "james",
	"jason", "joseph", "liam", "lucas", "mason", "matthew", "michael", "nathan", "noah", "oliver",
	"owen", "ryan", "samuel", "thomas", "william", "amelia", "ava", "charlotte", "chloe", "ella",
	"emily", "emma", "grace", "hannah", "isabella", "lily", "mia", "natalie", "olivia", "sophia",
}

var poolLastNames = []string{
	"anderson", "bennett", "brooks", "campbell", "carter", "clark", "collins", "cooper", "edwards", "evans",
	"foster", "green", "hall", "harris", "hill", "hughes", "jackson", "james", "kelly", "king",
	"lewis", "martin", "miller", "mitchell", "moore", "morgan", "morris", "nelson", "parker", "phillips",
	"reed", "richards", "roberts", "robinson", "rogers", "scott", "stewart", "taylor", "thompson", "walker",
}

func poolModeEnabled() bool {
	raw := strings.TrimSpace(os.Getenv(poolModeEnvironment))
	enabled, err := strconv.ParseBool(raw)
	return err == nil && enabled
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

func poolAuthFiles(now time.Time) []gin.H {
	files := make([]gin.H, 0, 300)
	for i := 1; i <= 300; i++ {
		first := poolFirstNames[(i*17+i/7)%len(poolFirstNames)]
		last := poolLastNames[(i*23+i/11)%len(poolLastNames)]
		suffix := 1000 + (i*7919)%9000
		domain := "example.net"
		if i%3 == 0 {
			domain = "example.org"
		}
		email := fmt.Sprintf("%s.%s%d@%s", first, last, suffix, domain)
		authIndex := fmt.Sprintf("claude-oauth-%04d", i)

		status := "active"
		statusMessage := ""
		disabled := false
		unavailable := false
		failed := int64(i % 3)
		if i%61 == 0 {
			status = "disabled"
			statusMessage = "Manually disabled"
			disabled = true
		} else if i%43 == 0 {
			status = "error"
			statusMessage = "Rate limit window is resetting"
			unavailable = true
			failed += 6
		}

		updated := now.UTC().Add(-time.Duration((i*37)%720) * time.Minute)
		created := updated.Add(-time.Duration(15+(i*19)%170) * 24 * time.Hour)
		plan := poolPlanForIndex(i)
		files = append(files, gin.H{
			"id":              authIndex,
			"auth_index":      authIndex,
			"name":            fmt.Sprintf("claude-%s.json", email),
			"type":            "claude",
			"provider":        "claude",
			"label":           "Claude Code",
			"account_type":    plan,
			"account":         fmt.Sprintf("user_%012x", 0x4a3c10000000+i*104729),
			"email":           email,
			"status":          status,
			"status_message":  statusMessage,
			"disabled":        disabled,
			"unavailable":     unavailable,
			"runtime_only":    false,
			"source":          "file",
			"size":            int64(1650 + (i*67)%780),
			"priority":        (i - 1) % 5,
			"note":            "",
			"success":         int64(860 + (i*137)%8900),
			"failed":          failed,
			"created_at":      created,
			"updated_at":      updated,
			"modtime":         updated,
			"last_refresh":    updated.Add(-time.Duration(2+i%17) * time.Minute),
			"recent_requests": poolRecentRequests(now, i),
		})
	}
	return files
}

func poolPlanForIndex(index int) string {
	switch {
	case index%17 == 0:
		return "Claude Team"
	case index%5 == 0:
		return "Claude Max"
	default:
		return "Claude Pro"
	}
}

func poolRecentRequests(now time.Time, seed int) []gin.H {
	anchor := now.UTC().Truncate(10 * time.Minute)
	buckets := make([]gin.H, 0, 20)
	for i := 19; i >= 0; i-- {
		buckets = append(buckets, gin.H{
			"time":    anchor.Add(-time.Duration(i) * 10 * time.Minute).Format(time.RFC3339),
			"success": int64(2 + (seed*7+i*5)%22),
			"failed":  int64((seed + i*3) % 3),
		})
	}
	return buckets
}

func poolModelsForAuth(_ string) []gin.H {
	models := []string{"claude-opus-4-6", "claude-sonnet-4-6", "claude-haiku-4-5"}
	result := make([]gin.H, 0, len(models))
	for _, model := range models {
		result = append(result, gin.H{"id": model, "display_name": model, "owned_by": "anthropic"})
	}
	return result
}

func poolLogLines(now time.Time, after int64, limit int) ([]string, int, int64) {
	levels := []string{"INFO", "INFO", "INFO", "DEBUG", "INFO", "INFO", "WARN"}
	models := []string{"claude-sonnet-4-6", "claude-sonnet-4-6", "claude-haiku-4-5", "claude-opus-4-6"}
	anchor := now.UTC().Truncate(30 * time.Second)
	lines := make([]string, 0, 240)
	latest := int64(0)
	for i := 239; i >= 0; i-- {
		ts := anchor.Add(-time.Duration(i) * 30 * time.Second)
		unix := ts.Unix()
		if unix > latest {
			latest = unix
		}
		if after > 0 && unix <= after {
			continue
		}
		account := 1 + int((unix/30+int64(i*29))%300)
		level := levels[i%len(levels)]
		model := models[(i+account)%len(models)]
		latency := 460 + (i*83+account*17)%4300
		requestID := fmt.Sprintf("req_%016x%08x", unix, account*65537+i)
		message := fmt.Sprintf("request completed provider=claude auth_index=claude-oauth-%04d model=%s status=200 latency_ms=%d request_id=%s", account, model, latency, requestID)
		if i%37 == 0 {
			level = "WARN"
			message = fmt.Sprintf("rate limit window nearing threshold provider=claude auth_index=claude-oauth-%04d remaining=%d%% request_id=%s", account, 7+(i+account)%16, requestID)
		}
		if i%83 == 0 {
			level = "ERROR"
			message = fmt.Sprintf("upstream request timed out provider=claude auth_index=claude-oauth-%04d status=504 retry=1 request_id=%s", account, requestID)
		}
		lines = append(lines, fmt.Sprintf("[%s] [%s] %s", ts.Format("2006-01-02 15:04:05"), level, message))
	}
	total := len(lines)
	if limit > 0 && len(lines) > limit {
		lines = lines[len(lines)-limit:]
	}
	return lines, total, latest
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
auth_index: claude-oauth-0083
model: claude-sonnet-4-6
status: 504
latency_ms: 30002
error: upstream request timeout
`, name)
}

func poolAuthNumber(authIndex string) (int, bool) {
	const prefix = "claude-oauth-"
	if !strings.HasPrefix(authIndex, prefix) {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimPrefix(authIndex, prefix))
	return n, err == nil && n >= 1 && n <= 300
}

func poolWindow(now time.Time, duration time.Duration, seed int, ceiling float64) gin.H {
	seconds := int64(duration / time.Second)
	startUnix := now.UTC().Unix() / seconds * seconds
	elapsed := float64(now.UTC().Unix()-startUnix) / float64(seconds)
	base := float64((seed*13)%12) + 2
	utilization := base + elapsed*(ceiling-base)
	if utilization > 99.4 {
		utilization = 99.4
	}
	return gin.H{
		"utilization": utilization,
		"resets_at":   time.Unix(startUnix+seconds, 0).UTC().Format(time.RFC3339),
	}
}

func poolUsage(now time.Time, index int) gin.H {
	fiveHour := poolWindow(now, 5*time.Hour, index, 78+float64(index%17))
	sevenDay := poolWindow(now, 7*24*time.Hour, index+5, 61+float64(index%26))
	usedCredits := 2850 + (index*739)%14200
	monthlyLimit := 20000
	if poolPlanForIndex(index) == "Claude Max" {
		monthlyLimit = 50000
	}
	return gin.H{
		"five_hour":            fiveHour,
		"seven_day":            sevenDay,
		"seven_day_oauth_apps": poolWindow(now, 7*24*time.Hour, index+11, 48+float64(index%29)),
		"seven_day_opus":       poolWindow(now, 7*24*time.Hour, index+19, 42+float64(index%31)),
		"seven_day_sonnet":     poolWindow(now, 7*24*time.Hour, index+23, 67+float64(index%24)),
		"seven_day_cowork":     poolWindow(now, 7*24*time.Hour, index+31, 35+float64(index%27)),
		"extra_usage": gin.H{
			"is_enabled":    index%4 != 0,
			"used_credits":  usedCredits,
			"monthly_limit": monthlyLimit,
		},
	}
}

func poolProfile(index int) gin.H {
	plan := poolPlanForIndex(index)
	account := gin.H{
		"uuid":           fmt.Sprintf("%08x-%04x-4%03x-8%03x-%012x", index*104729, index, index%4096, index%4096, index*99991),
		"has_claude_max": plan == "Claude Max",
		"has_claude_pro": plan == "Claude Pro",
	}
	profile := gin.H{"account": account}
	if plan == "Claude Team" {
		profile["organization"] = gin.H{
			"uuid":                fmt.Sprintf("org_%016x", index*32452843),
			"organization_type":   "claude_team",
			"subscription_status": "active",
		}
	}
	return profile
}

func poolAPICall(c *gin.Context, body apiCallRequest) {
	method := strings.ToUpper(strings.TrimSpace(body.Method))
	if method != http.MethodGet {
		c.JSON(http.StatusForbidden, gin.H{"error": "request is not available"})
		return
	}
	authIndex := firstNonEmptyString(body.AuthIndexSnake, body.AuthIndexCamel, body.AuthIndexPascal)
	index, ok := poolAuthNumber(authIndex)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "auth file not found"})
		return
	}
	var payload gin.H
	switch strings.TrimSpace(body.URL) {
	case "https://api.anthropic.com/api/oauth/usage":
		payload = poolUsage(time.Now(), index)
	case "https://api.anthropic.com/api/oauth/profile":
		payload = poolProfile(index)
	default:
		c.JSON(http.StatusForbidden, gin.H{"error": "request is not available"})
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
