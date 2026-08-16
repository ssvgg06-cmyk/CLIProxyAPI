package management

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

const (
	poolStateVersion       = 1
	poolInitialAccounts    = 300
	poolMinimumAccounts    = 250
	poolMaximumAccounts    = 350
	poolRetiredGracePeriod = 15 * time.Minute
	poolMaximumLogLines    = 1200
)

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

var poolModelIDs = []string{
	"claude-fable-5",
	"claude-opus-4-8",
	"claude-sonnet-5",
	"claude-haiku-4-5-20251001",
}

type poolQuotaWindow struct {
	Utilization   float64   `json:"utilization"`
	RatePerMinute float64   `json:"rate_per_minute"`
	ResetAt       time.Time `json:"reset_at"`
}

type poolAccount struct {
	ID                 uint64          `json:"id"`
	AuthIndex          string          `json:"auth_index"`
	Email              string          `json:"email"`
	Name               string          `json:"name"`
	Plan               string          `json:"plan"`
	Account            string          `json:"account"`
	Status             string          `json:"status"`
	StatusMessage      string          `json:"status_message"`
	Disabled           bool            `json:"disabled"`
	Unavailable        bool            `json:"unavailable"`
	StatusUntil        time.Time       `json:"status_until,omitempty"`
	CreatedAt          time.Time       `json:"created_at"`
	UpdatedAt          time.Time       `json:"updated_at"`
	LastRefresh        time.Time       `json:"last_refresh"`
	RetiredAt          time.Time       `json:"retired_at,omitempty"`
	Success            int64           `json:"success"`
	Failed             int64           `json:"failed"`
	Priority           int             `json:"priority"`
	FiveHour           poolQuotaWindow `json:"five_hour"`
	SevenDay           poolQuotaWindow `json:"seven_day"`
	SevenDayOAuthApps  poolQuotaWindow `json:"seven_day_oauth_apps"`
	SevenDayOpus       poolQuotaWindow `json:"seven_day_opus"`
	SevenDaySonnet     poolQuotaWindow `json:"seven_day_sonnet"`
	SevenDayCowork     poolQuotaWindow `json:"seven_day_cowork"`
	ExtraUsageEnabled  bool            `json:"extra_usage_enabled"`
	ExtraUsedCredits   int             `json:"extra_used_credits"`
	ExtraMonthlyLimit  int             `json:"extra_monthly_limit"`
	ExhaustedRefreshes int             `json:"exhausted_refreshes"`
	RetireAfter        int             `json:"retire_after"`
}

type poolLogEntry struct {
	Timestamp int64  `json:"timestamp"`
	Line      string `json:"line"`
}

type poolPersistentState struct {
	Version     int            `json:"version"`
	Seed        int64          `json:"seed"`
	Revision    uint64         `json:"revision"`
	NextAccount uint64         `json:"next_account"`
	LastLogAt   time.Time      `json:"last_log_at"`
	Accounts    []*poolAccount `json:"accounts"`
	Retired     []*poolAccount `json:"retired"`
	Logs        []poolLogEntry `json:"logs"`
}

type poolSimulator struct {
	mu    sync.Mutex
	path  string
	state poolPersistentState
}

func newPoolSimulator(path string, now time.Time, seed int64) *poolSimulator {
	simulator := &poolSimulator{path: strings.TrimSpace(path)}
	if simulator.load() == nil {
		return simulator
	}
	if seed == 0 {
		seed = now.UTC().UnixNano()
	}
	simulator.state = poolPersistentState{
		Version:   poolStateVersion,
		Seed:      seed,
		LastLogAt: now.UTC().Add(-2 * time.Hour).Truncate(30 * time.Second),
		Accounts:  make([]*poolAccount, 0, poolInitialAccounts),
		Retired:   make([]*poolAccount, 0),
		Logs:      make([]poolLogEntry, 0, 256),
	}
	for len(simulator.state.Accounts) < poolInitialAccounts {
		account := simulator.newAccountLocked(now.UTC(), false)
		if account.ID%61 == 0 {
			simulator.setTemporaryStatusLocked(account, "disabled", now.UTC().Add(45*time.Minute))
		} else if account.ID%43 == 0 {
			simulator.setTemporaryStatusLocked(account, "error", now.UTC().Add(30*time.Minute))
		}
		simulator.state.Accounts = append(simulator.state.Accounts, account)
	}
	simulator.syncLogsLocked(now.UTC())
	if errPersist := simulator.persistLocked(); errPersist != nil {
		log.WithError(errPersist).Warn("failed to persist initial credential pool state")
	}
	return simulator
}

func (s *poolSimulator) load() error {
	if s.path == "" {
		return os.ErrNotExist
	}
	data, errRead := os.ReadFile(s.path)
	if errRead != nil {
		return errRead
	}
	var state poolPersistentState
	if errUnmarshal := json.Unmarshal(data, &state); errUnmarshal != nil {
		log.WithError(errUnmarshal).Warn("credential pool state is invalid; rebuilding")
		return errUnmarshal
	}
	if state.Version != poolStateVersion || len(state.Accounts) == 0 || state.Seed == 0 {
		return fmt.Errorf("unsupported credential pool state")
	}
	s.state = state
	return nil
}

func (s *poolSimulator) persistLocked() error {
	if s.path == "" {
		return nil
	}
	dir := filepath.Dir(s.path)
	if errMkdir := os.MkdirAll(dir, 0o700); errMkdir != nil {
		return fmt.Errorf("create state directory: %w", errMkdir)
	}
	temporary, errCreate := os.CreateTemp(dir, ".pool-state-*.json")
	if errCreate != nil {
		return fmt.Errorf("create temporary state: %w", errCreate)
	}
	temporaryName := temporary.Name()
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = os.Remove(temporaryName)
		}
	}()
	encoder := json.NewEncoder(temporary)
	if errEncode := encoder.Encode(&s.state); errEncode != nil {
		_ = temporary.Close()
		return fmt.Errorf("encode state: %w", errEncode)
	}
	if errSync := temporary.Sync(); errSync != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync state: %w", errSync)
	}
	if errClose := temporary.Close(); errClose != nil {
		return fmt.Errorf("close state: %w", errClose)
	}
	if errChmod := os.Chmod(temporaryName, 0o600); errChmod != nil {
		return fmt.Errorf("secure state: %w", errChmod)
	}
	if errRename := os.Rename(temporaryName, s.path); errRename != nil {
		return fmt.Errorf("replace state: %w", errRename)
	}
	removeTemporary = false
	return nil
}

func (s *poolSimulator) randomLocked(salt string) float64 {
	source := fmt.Sprintf("%d:%d:%d:%s", s.state.Seed, s.state.Revision, s.state.NextAccount, salt)
	sum := sha256.Sum256([]byte(source))
	value := binary.BigEndian.Uint64(sum[:8])
	return float64(value>>11) / float64(uint64(1)<<53)
}

func (s *poolSimulator) authFiles(now time.Time, advance bool) []gin.H {
	s.mu.Lock()
	defer s.mu.Unlock()
	now = now.UTC()
	if advance {
		s.advanceLocked(now)
		if errPersist := s.persistLocked(); errPersist != nil {
			log.WithError(errPersist).Warn("failed to persist credential pool state")
		}
	}
	files := make([]gin.H, 0, len(s.state.Accounts))
	for _, account := range s.state.Accounts {
		files = append(files, s.authFileLocked(account, now))
	}
	sort.Slice(files, func(i, j int) bool {
		return files[i]["name"].(string) < files[j]["name"].(string)
	})
	return files
}

func (s *poolSimulator) advanceLocked(now time.Time) {
	previousCount := len(s.state.Accounts)
	s.state.Revision++
	s.cleanupRetiredLocked(now)

	retained := make([]*poolAccount, 0, len(s.state.Accounts))
	replacementsNeeded := 0
	for _, account := range s.state.Accounts {
		s.applyElapsedLocked(account, now)
		s.applyRefreshUsageLocked(account)
		if s.accountExhaustedLocked(account) {
			account.ExhaustedRefreshes++
			if account.StatusMessage != "Quota exhausted" {
				account.Status = "error"
				account.StatusMessage = "Quota exhausted"
				account.Unavailable = true
				account.Disabled = false
				account.RetireAfter = 1 + int(s.randomLocked(fmt.Sprintf("retire-%d", account.ID))*3)
				s.appendEventLocked(now, "WARN", fmt.Sprintf("quota exhausted provider=claude auth_index=%s email=%s", account.AuthIndex, account.Email))
			}
			if account.ExhaustedRefreshes >= account.RetireAfter {
				s.retireLocked(account, now, "quota depleted")
				replacementsNeeded++
				continue
			}
		} else if account.Status != "active" && !account.StatusUntil.IsZero() && !now.Before(account.StatusUntil) {
			s.setActiveLocked(account)
			s.appendEventLocked(now, "INFO", fmt.Sprintf("credential restored provider=claude auth_index=%s email=%s", account.AuthIndex, account.Email))
		}
		retained = append(retained, account)
	}
	s.state.Accounts = retained
	for replacementsNeeded > 0 {
		account := s.newAccountLocked(now, true)
		s.state.Accounts = append(s.state.Accounts, account)
		s.appendEventLocked(now, "INFO", fmt.Sprintf("credential registered provider=claude auth_index=%s email=%s plan=%s", account.AuthIndex, account.Email, account.Plan))
		replacementsNeeded--
	}

	s.reconcileStatusesLocked(now)
	delta := 1 + int(s.randomLocked("population-delta")*5)
	if previousCount >= poolMaximumAccounts || (previousCount > poolMinimumAccounts && s.randomLocked("population-direction") < 0.5) {
		delta = -delta
	}
	target := previousCount + delta
	if target < poolMinimumAccounts {
		target = poolMinimumAccounts + (poolMinimumAccounts - target)
	}
	if target > poolMaximumAccounts {
		target = poolMaximumAccounts - (target - poolMaximumAccounts)
	}
	if target == previousCount {
		if previousCount < poolMaximumAccounts {
			target++
		} else {
			target--
		}
	}

	for len(s.state.Accounts) > target {
		index := s.highestUtilizationIndexLocked()
		account := s.state.Accounts[index]
		s.retireLocked(account, now, "pool capacity adjusted")
		s.state.Accounts = append(s.state.Accounts[:index], s.state.Accounts[index+1:]...)
	}
	for len(s.state.Accounts) < target {
		account := s.newAccountLocked(now, true)
		s.state.Accounts = append(s.state.Accounts, account)
		s.appendEventLocked(now, "INFO", fmt.Sprintf("credential registered provider=claude auth_index=%s email=%s plan=%s", account.AuthIndex, account.Email, account.Plan))
	}
	s.syncLogsLocked(now)
}

func (s *poolSimulator) applyElapsedLocked(account *poolAccount, now time.Time) {
	if !now.After(account.UpdatedAt) {
		return
	}
	minutes := now.Sub(account.UpdatedAt).Minutes()
	s.advanceWindowLocked(&account.FiveHour, account, now, minutes, 5*time.Hour, "five-hour")
	s.advanceWindowLocked(&account.SevenDay, account, now, minutes, 7*24*time.Hour, "seven-day")
	s.advanceWindowLocked(&account.SevenDayOAuthApps, account, now, minutes, 7*24*time.Hour, "oauth-apps")
	s.advanceWindowLocked(&account.SevenDayOpus, account, now, minutes, 7*24*time.Hour, "opus")
	s.advanceWindowLocked(&account.SevenDaySonnet, account, now, minutes, 7*24*time.Hour, "sonnet")
	s.advanceWindowLocked(&account.SevenDayCowork, account, now, minutes, 7*24*time.Hour, "cowork")
	account.ExtraUsedCredits += int(minutes * account.SevenDay.RatePerMinute * 2)
	if account.ExtraUsedCredits > account.ExtraMonthlyLimit {
		account.ExtraUsedCredits = account.ExtraMonthlyLimit
	}
	account.UpdatedAt = now
	account.LastRefresh = now
}

func (s *poolSimulator) advanceWindowLocked(window *poolQuotaWindow, account *poolAccount, now time.Time, minutes float64, duration time.Duration, salt string) {
	if window.ResetAt.IsZero() {
		window.ResetAt = now.Add(duration)
	}
	if !now.Before(window.ResetAt) {
		for !now.Before(window.ResetAt) {
			window.ResetAt = window.ResetAt.Add(duration)
		}
		window.Utilization = s.randomLocked(fmt.Sprintf("reset-%d-%s", account.ID, salt)) * 3
	}
	window.Utilization = clampPoolUtilization(window.Utilization + minutes*window.RatePerMinute)
}

func (s *poolSimulator) applyRefreshUsageLocked(account *poolAccount) {
	base := 0.05 + s.randomLocked(fmt.Sprintf("refresh-%d", account.ID))*0.10
	account.FiveHour.Utilization = clampPoolUtilization(account.FiveHour.Utilization + base*1.4)
	account.SevenDay.Utilization = clampPoolUtilization(account.SevenDay.Utilization + base)
	account.SevenDayOAuthApps.Utilization = clampPoolUtilization(account.SevenDayOAuthApps.Utilization + base*0.8)
	account.SevenDayOpus.Utilization = clampPoolUtilization(account.SevenDayOpus.Utilization + base*0.7)
	account.SevenDaySonnet.Utilization = clampPoolUtilization(account.SevenDaySonnet.Utilization + base*1.1)
	account.SevenDayCowork.Utilization = clampPoolUtilization(account.SevenDayCowork.Utilization + base*0.6)
	account.Success += int64(2 + int(base*100)%7)
}

func (s *poolSimulator) accountExhaustedLocked(account *poolAccount) bool {
	return account.FiveHour.Utilization >= 100 || account.SevenDay.Utilization >= 100
}

func (s *poolSimulator) reconcileStatusesLocked(now time.Time) {
	abnormal := 0
	active := make([]*poolAccount, 0, len(s.state.Accounts))
	for _, account := range s.state.Accounts {
		if account.Status == "active" {
			active = append(active, account)
		} else {
			abnormal++
		}
	}
	target := int(math.Ceil(float64(len(s.state.Accounts)) * (0.02 + s.randomLocked("abnormal-target")*0.04)))
	changes := 1 + int(s.randomLocked("abnormal-changes")*2)
	for abnormal < target && len(active) > 0 && changes > 0 {
		index := int(s.randomLocked(fmt.Sprintf("abnormal-pick-%d", changes)) * float64(len(active)))
		if index >= len(active) {
			index = len(active) - 1
		}
		account := active[index]
		status := "error"
		if s.randomLocked(fmt.Sprintf("abnormal-kind-%d", account.ID)) < 0.35 {
			status = "disabled"
		}
		duration := time.Duration(30+int(s.randomLocked(fmt.Sprintf("abnormal-duration-%d", account.ID))*90)) * time.Minute
		s.setTemporaryStatusLocked(account, status, now.Add(duration))
		s.appendEventLocked(now, "WARN", fmt.Sprintf("credential %s provider=claude auth_index=%s email=%s", status, account.AuthIndex, account.Email))
		active = append(active[:index], active[index+1:]...)
		abnormal++
		changes--
	}
}

func (s *poolSimulator) setTemporaryStatusLocked(account *poolAccount, status string, until time.Time) {
	account.Status = status
	account.StatusUntil = until
	account.Disabled = status == "disabled"
	account.Unavailable = status == "error"
	if status == "disabled" {
		account.StatusMessage = "Account suspended"
	} else {
		account.StatusMessage = "Authentication temporarily unavailable"
		account.Failed++
	}
}

func (s *poolSimulator) setActiveLocked(account *poolAccount) {
	account.Status = "active"
	account.StatusMessage = ""
	account.StatusUntil = time.Time{}
	account.Disabled = false
	account.Unavailable = false
}

func (s *poolSimulator) retireLocked(account *poolAccount, now time.Time, reason string) {
	account.RetiredAt = now
	s.state.Retired = append(s.state.Retired, account)
	s.appendEventLocked(now, "INFO", fmt.Sprintf("credential removed provider=claude auth_index=%s email=%s reason=%q", account.AuthIndex, account.Email, reason))
}

func (s *poolSimulator) cleanupRetiredLocked(now time.Time) {
	retained := s.state.Retired[:0]
	for _, account := range s.state.Retired {
		if account.RetiredAt.IsZero() || now.Sub(account.RetiredAt) <= poolRetiredGracePeriod {
			retained = append(retained, account)
		}
	}
	s.state.Retired = retained
}

func (s *poolSimulator) highestUtilizationIndexLocked() int {
	index := 0
	highest := -1.0
	for i, account := range s.state.Accounts {
		value := math.Max(account.FiveHour.Utilization, account.SevenDay.Utilization)
		if value > highest {
			highest = value
			index = i
		}
	}
	return index
}

func (s *poolSimulator) newAccountLocked(now time.Time, fresh bool) *poolAccount {
	s.state.NextAccount++
	id := s.state.NextAccount
	createdAt := now.Add(-time.Duration(20+int(s.randomLocked(fmt.Sprintf("age-%d", id))*2400)) * time.Minute)
	if fresh {
		createdAt = now.Add(-time.Duration(1+int(s.randomLocked(fmt.Sprintf("fresh-age-%d", id))*8)) * time.Minute)
	}
	email := s.maskedEmailLocked(id)
	authHash := sha256.Sum256([]byte(fmt.Sprintf("%d:%d:%d", s.state.Seed, id, createdAt.UnixNano())))
	authIndex := fmt.Sprintf("claude-oauth-%x", authHash[:10])
	initial := func(salt string) float64 {
		if fresh {
			return s.randomLocked(fmt.Sprintf("fresh-%d-%s", id, salt)) * 3
		}
		return 3 + s.randomLocked(fmt.Sprintf("initial-%d-%s", id, salt))*96.5
	}
	rate := func(salt string) float64 {
		return 0.01 + s.randomLocked(fmt.Sprintf("rate-%d-%s", id, salt))*0.03
	}
	plan := poolPlanForID(id)
	monthlyLimit := 20000
	if plan == "Claude Max" {
		monthlyLimit = 50000
	}
	return &poolAccount{
		ID:                id,
		AuthIndex:         authIndex,
		Email:             email,
		Name:              fmt.Sprintf("claude-%s.json", email),
		Plan:              plan,
		Account:           fmt.Sprintf("user_%012x", 0x4a3c10000000+id*104729),
		Status:            "active",
		CreatedAt:         createdAt,
		UpdatedAt:         now,
		LastRefresh:       now,
		Success:           int64(320 + (id*137)%8900),
		Failed:            int64(id % 3),
		Priority:          int((id - 1) % 5),
		FiveHour:          poolQuotaWindow{Utilization: initial("five"), RatePerMinute: rate("five"), ResetAt: now.Add(5 * time.Hour)},
		SevenDay:          poolQuotaWindow{Utilization: initial("seven"), RatePerMinute: rate("seven"), ResetAt: now.Add(7 * 24 * time.Hour)},
		SevenDayOAuthApps: poolQuotaWindow{Utilization: initial("oauth"), RatePerMinute: rate("oauth"), ResetAt: now.Add(7 * 24 * time.Hour)},
		SevenDayOpus:      poolQuotaWindow{Utilization: initial("opus"), RatePerMinute: rate("opus"), ResetAt: now.Add(7 * 24 * time.Hour)},
		SevenDaySonnet:    poolQuotaWindow{Utilization: initial("sonnet"), RatePerMinute: rate("sonnet"), ResetAt: now.Add(7 * 24 * time.Hour)},
		SevenDayCowork:    poolQuotaWindow{Utilization: initial("cowork"), RatePerMinute: rate("cowork"), ResetAt: now.Add(7 * 24 * time.Hour)},
		ExtraUsageEnabled: id%4 != 0,
		ExtraUsedCredits:  850 + int((id*739)%14200),
		ExtraMonthlyLimit: monthlyLimit,
		RetireAfter:       1 + int(id%3),
	}
}

func (s *poolSimulator) maskedEmailLocked(id uint64) string {
	first := poolFirstNames[(id*17+id/7)%uint64(len(poolFirstNames))]
	last := poolLastNames[(id*23+id/11)%uint64(len(poolLastNames))]
	prefix := first
	if len(prefix) > 2 {
		prefix = prefix[:2]
	}
	number := 100000 + int((id*7919+uint64(len(last))*104729)%900000)
	stars := strings.Repeat("*", 4+int(id%5))
	return fmt.Sprintf("%s%s%04d@gmail.com", prefix, stars, number%10000)
}

func poolPlanForID(id uint64) string {
	switch {
	case id%17 == 0:
		return "Claude Team"
	case id%5 == 0:
		return "Claude Max"
	default:
		return "Claude Pro"
	}
}

func (s *poolSimulator) authFileLocked(account *poolAccount, now time.Time) gin.H {
	return gin.H{
		"id":              account.AuthIndex,
		"auth_index":      account.AuthIndex,
		"name":            account.Name,
		"type":            "claude",
		"provider":        "claude",
		"label":           "Claude Code",
		"account_type":    account.Plan,
		"account":         account.Account,
		"email":           account.Email,
		"status":          account.Status,
		"status_message":  account.StatusMessage,
		"disabled":        account.Disabled,
		"unavailable":     account.Unavailable,
		"runtime_only":    false,
		"source":          "file",
		"size":            int64(1650 + (account.ID*67)%780),
		"priority":        account.Priority,
		"note":            "",
		"success":         account.Success,
		"failed":          account.Failed,
		"created_at":      account.CreatedAt,
		"updated_at":      account.UpdatedAt,
		"modtime":         account.UpdatedAt,
		"last_refresh":    account.LastRefresh,
		"recent_requests": s.recentRequestsLocked(account, now),
	}
}

func (s *poolSimulator) recentRequestsLocked(account *poolAccount, now time.Time) []gin.H {
	anchor := now.UTC().Truncate(10 * time.Minute)
	buckets := make([]gin.H, 0, 20)
	for i := 19; i >= 0; i-- {
		buckets = append(buckets, gin.H{
			"time":    anchor.Add(-time.Duration(i) * 10 * time.Minute).Format(time.RFC3339),
			"success": int64(2 + (int(account.ID)*7+i*5+int(s.state.Revision))%22),
			"failed":  int64((int(account.ID) + i*3) % 3),
		})
	}
	return buckets
}

func (s *poolSimulator) projectedWindowLocked(account *poolAccount, window poolQuotaWindow, now time.Time) gin.H {
	utilization := window.Utilization
	if now.After(account.UpdatedAt) && now.Before(window.ResetAt) {
		utilization += now.Sub(account.UpdatedAt).Minutes() * window.RatePerMinute
	}
	return gin.H{
		"utilization": clampPoolUtilization(utilization),
		"resets_at":   window.ResetAt.UTC().Format(time.RFC3339),
	}
}

func (s *poolSimulator) usage(now time.Time, authIndex string) (gin.H, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	account := s.findAccountLocked(authIndex)
	if account == nil {
		return nil, false
	}
	now = now.UTC()
	return gin.H{
		"five_hour":            s.projectedWindowLocked(account, account.FiveHour, now),
		"seven_day":            s.projectedWindowLocked(account, account.SevenDay, now),
		"seven_day_oauth_apps": s.projectedWindowLocked(account, account.SevenDayOAuthApps, now),
		"seven_day_opus":       s.projectedWindowLocked(account, account.SevenDayOpus, now),
		"seven_day_sonnet":     s.projectedWindowLocked(account, account.SevenDaySonnet, now),
		"seven_day_cowork":     s.projectedWindowLocked(account, account.SevenDayCowork, now),
		"extra_usage": gin.H{
			"is_enabled":    account.ExtraUsageEnabled,
			"used_credits":  account.ExtraUsedCredits,
			"monthly_limit": account.ExtraMonthlyLimit,
		},
	}, true
}

func (s *poolSimulator) profile(authIndex string) (gin.H, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	account := s.findAccountLocked(authIndex)
	if account == nil {
		return nil, false
	}
	profileAccount := gin.H{
		"uuid":           fmt.Sprintf("%08x-%04x-4%03x-8%03x-%012x", account.ID*104729, account.ID, account.ID%4096, account.ID%4096, account.ID*99991),
		"has_claude_max": account.Plan == "Claude Max",
		"has_claude_pro": account.Plan == "Claude Pro",
	}
	profile := gin.H{"account": profileAccount}
	if account.Plan == "Claude Team" {
		profile["organization"] = gin.H{
			"uuid":                fmt.Sprintf("org_%016x", account.ID*32452843),
			"organization_type":   "claude_team",
			"subscription_status": "active",
		}
	}
	return profile, true
}

func (s *poolSimulator) findAccountLocked(authIndex string) *poolAccount {
	for _, account := range s.state.Accounts {
		if account.AuthIndex == authIndex {
			return account
		}
	}
	for _, account := range s.state.Retired {
		if account.AuthIndex == authIndex {
			return account
		}
	}
	return nil
}

func (s *poolSimulator) syncLogsLocked(now time.Time) bool {
	anchor := now.UTC().Truncate(30 * time.Second)
	if s.state.LastLogAt.IsZero() {
		s.state.LastLogAt = anchor.Add(-2 * time.Hour)
	}
	changed := false
	for timestamp := s.state.LastLogAt.Add(30 * time.Second); !timestamp.After(anchor); timestamp = timestamp.Add(30 * time.Second) {
		if len(s.state.Accounts) == 0 {
			break
		}
		index := int((timestamp.Unix()/30 + int64(s.state.Revision)) % int64(len(s.state.Accounts)))
		account := s.state.Accounts[index]
		model := poolModelIDs[int((timestamp.Unix()/30+int64(account.ID))%int64(len(poolModelIDs)))]
		latency := 460 + int((timestamp.Unix()+int64(account.ID)*83)%4300)
		requestHash := sha256.Sum256([]byte(fmt.Sprintf("%d:%d:%d", s.state.Seed, timestamp.Unix(), account.ID)))
		requestID := fmt.Sprintf("req_%x", requestHash[:12])
		level := "INFO"
		message := fmt.Sprintf("request completed provider=claude auth_index=%s model=%s status=200 latency_ms=%d request_id=%s", account.AuthIndex, model, latency, requestID)
		if timestamp.Unix()/30%37 == 0 {
			level = "WARN"
			message = fmt.Sprintf("rate limit window nearing threshold provider=claude auth_index=%s remaining=%d%% request_id=%s", account.AuthIndex, 7+int(account.ID%16), requestID)
		}
		if timestamp.Unix()/30%83 == 0 {
			level = "ERROR"
			message = fmt.Sprintf("upstream request timed out provider=claude auth_index=%s model=%s status=504 retry=1 request_id=%s", account.AuthIndex, model, requestID)
		}
		s.appendEventLocked(timestamp, level, message)
		s.state.LastLogAt = timestamp
		changed = true
	}
	return changed
}

func (s *poolSimulator) appendEventLocked(timestamp time.Time, level, message string) {
	line := fmt.Sprintf("[%s] [%s] %s", timestamp.UTC().Format("2006-01-02 15:04:05"), level, message)
	s.state.Logs = append(s.state.Logs, poolLogEntry{Timestamp: timestamp.UTC().Unix(), Line: line})
	if len(s.state.Logs) > poolMaximumLogLines {
		s.state.Logs = append([]poolLogEntry(nil), s.state.Logs[len(s.state.Logs)-poolMaximumLogLines:]...)
	}
}

func (s *poolSimulator) logLines(now time.Time, after int64, limit int) ([]string, int, int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.syncLogsLocked(now.UTC()) {
		if errPersist := s.persistLocked(); errPersist != nil {
			log.WithError(errPersist).Warn("failed to persist credential pool logs")
		}
	}
	entries := append([]poolLogEntry(nil), s.state.Logs...)
	sort.SliceStable(entries, func(i, j int) bool {
		return entries[i].Timestamp < entries[j].Timestamp
	})
	lines := make([]string, 0, len(entries))
	latest := after
	for _, entry := range entries {
		if entry.Timestamp > latest {
			latest = entry.Timestamp
		}
		if after > 0 && entry.Timestamp <= after {
			continue
		}
		lines = append(lines, entry.Line)
	}
	total := len(lines)
	if limit > 0 && len(lines) > limit {
		lines = lines[len(lines)-limit:]
	}
	return lines, total, latest
}

func clampPoolUtilization(value float64) float64 {
	if value < 0 {
		return 0
	}
	if value > 100 {
		return 100
	}
	return value
}
