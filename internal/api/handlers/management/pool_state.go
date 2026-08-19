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
	poolStateVersion    = 4
	poolInitialAccounts = 300
	poolMinimumAccounts = 250
	poolMaximumAccounts = 350

	// poolRetiredGracePeriod keeps the full account record available to quota and
	// profile lookups briefly after retirement. Long-term log correlation uses the
	// separate minimal history archive below.
	poolRetiredGracePeriod = 15 * time.Minute

	// poolEpochSeconds is the wall-clock simulation step. Pool evolution is keyed
	// to this epoch rather than to the number of HTTP requests received, which
	// keeps every past state reproducible from (seed, timestamp) alone.
	poolEpochSeconds = 300

	// poolHistoryWindow is how far back logs and safe retired-account snapshots
	// stay queryable. Full quota records use poolRetiredGracePeriod instead.
	poolHistoryWindow = 90 * 24 * time.Hour

	// poolMaxCatchUpEpochs bounds a single catch-up run after downtime. Quota
	// drift is recomputed from elapsed time regardless, so skipping epochs only
	// skips lifecycle events that never happened while the pool was stopped.
	poolMaxCatchUpEpochs = 288

	// poolDefaultTailWindow is the range served when no explicit range is given.
	poolDefaultTailWindow = 30 * time.Minute

	// poolDefaultLogLimit and poolMaxLogLimit bound a single log response.
	poolDefaultLogLimit = 2000
	poolMaxLogLimit     = 20000

	poolEventRetention = poolHistoryWindow

	// poolMaximumEvents bounds the persisted lifecycle trail so the state file
	// stays small even across the full retention window.
	poolMaximumEvents = 20000

	// poolMaximumRequestMappings matches the bounded New API cache. Associations
	// outside this working set remain reproducible from the projected roster.
	poolMaximumRequestMappings = 20000
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

// poolModelIDs is the fixed model snapshot advertised by every pool credential.
// Real New API logs may contain other claude-* model IDs, but never mutate this
// authentication-file capability list.
var poolModelIDs = []string{
	"claude-fable-5",
	"claude-opus-4-8",
	"claude-sonnet-5",
	"claude-haiku-4-5-20251001",
}

// poolHourlyRPM maps a UTC hour to the mean requests-per-minute the pool serves.
var poolHourlyRPM = [24]float64{
	9.05, 10.69, 43.45, 50.03, 57.06, 52.15, 69.90, 38.29,
	34.89, 18.35, 11.04, 12.49, 34.27, 21.23, 18.41, 35.11,
	29.88, 42.70, 51.65, 53.33, 46.81, 22.24, 13.28, 11.17,
}

type poolQuotaWindow struct {
	Utilization   float64   `json:"utilization"`
	RatePerMinute float64   `json:"rate_per_minute"`
	ResetAt       time.Time `json:"reset_at"`
}

type poolAccount struct {
	ID                uint64          `json:"id"`
	AuthIndex         string          `json:"auth_index"`
	Email             string          `json:"email"`
	Name              string          `json:"name"`
	Plan              string          `json:"plan"`
	Account           string          `json:"account"`
	Status            string          `json:"status"`
	StatusMessage     string          `json:"status_message"`
	Disabled          bool            `json:"disabled"`
	Unavailable       bool            `json:"unavailable"`
	StatusUntil       time.Time       `json:"status_until,omitempty"`
	FirstSeen         time.Time       `json:"first_seen"`
	CreatedAt         time.Time       `json:"created_at"`
	UpdatedAt         time.Time       `json:"updated_at"`
	LastRefresh       time.Time       `json:"last_refresh"`
	RetiredAt         time.Time       `json:"retired_at,omitempty"`
	RetiredReason     string          `json:"retired_reason,omitempty"`
	Success           int64           `json:"success"`
	Failed            int64           `json:"failed"`
	Priority          int             `json:"priority"`
	FiveHour          poolQuotaWindow `json:"five_hour"`
	SevenDay          poolQuotaWindow `json:"seven_day"`
	SevenDayOAuthApps poolQuotaWindow `json:"seven_day_oauth_apps"`
	SevenDayOpus      poolQuotaWindow `json:"seven_day_opus"`
	SevenDaySonnet    poolQuotaWindow `json:"seven_day_sonnet"`
	SevenDayCowork    poolQuotaWindow `json:"seven_day_cowork"`
	ExtraUsageEnabled bool            `json:"extra_usage_enabled"`
	ExtraUsedCredits  int             `json:"extra_used_credits"`
	ExtraMonthlyLimit int             `json:"extra_monthly_limit"`
}

// poolLogQuotaSummary is the non-sensitive last-known quota state retained for
// a log detail card. It deliberately excludes tokens and credential material.
type poolLogQuotaSummary struct {
	FiveHourUtilization float64   `json:"five_hour_utilization"`
	SevenDayUtilization float64   `json:"seven_day_utilization"`
	UpdatedAt           time.Time `json:"updated_at"`
}

// poolLogAccount is the immutable account snapshot retained for log
// correlation after the full quota tombstone expires. Values of this type are
// safe to return to callers because they contain no pointers, tokens, or
// mutable credential state.
type poolLogAccount struct {
	ID            uint64              `json:"id"`
	AuthIndex     string              `json:"auth_index"`
	Email         string              `json:"email"`
	Name          string              `json:"name"`
	Account       string              `json:"account,omitempty"`
	Plan          string              `json:"plan"`
	Status        string              `json:"status"`
	StatusMessage string              `json:"status_message,omitempty"`
	Priority      int                 `json:"priority"`
	Success       int64               `json:"success"`
	Failed        int64               `json:"failed"`
	FirstSeen     time.Time           `json:"first_seen"`
	RetiredAt     time.Time           `json:"retired_at,omitempty"`
	Current       bool                `json:"current"`
	Quota         poolLogQuotaSummary `json:"quota"`
}

// poolRequestMapping pins the presentation credential selected the first time
// a real New API request is rendered. Pool lifecycle epochs can be materialized
// later than the request itself, so recomputing solely from a historical roster
// would otherwise allow the same opaque request ID to move between accounts.
// Only the opaque request ID, a safe auth index and the source timestamp are
// retained; no New API user, token, prompt or response data enters pool state.
type poolRequestMapping struct {
	AuthIndex string         `json:"auth_index"`
	RequestAt time.Time      `json:"request_at"`
	Account   poolLogAccount `json:"account"`
}

func newPoolLogAccount(account *poolAccount) poolLogAccount {
	if account == nil {
		return poolLogAccount{}
	}
	return poolLogAccount{
		ID:            account.ID,
		AuthIndex:     account.AuthIndex,
		Email:         account.Email,
		Name:          account.Name,
		Account:       account.Account,
		Plan:          account.Plan,
		Status:        account.Status,
		StatusMessage: account.StatusMessage,
		Priority:      account.Priority,
		Success:       account.Success,
		Failed:        account.Failed,
		FirstSeen:     account.FirstSeen,
		RetiredAt:     account.RetiredAt,
		Current:       account.RetiredAt.IsZero(),
		Quota: poolLogQuotaSummary{
			FiveHourUtilization: account.FiveHour.Utilization,
			SevenDayUtilization: account.SevenDay.Utilization,
			UpdatedAt:           account.UpdatedAt,
		},
	}
}

// activeAt reports whether the archived identity belonged to the roster at t.
func (a poolLogAccount) activeAt(t time.Time) bool {
	if a.FirstSeen.IsZero() || t.Before(a.FirstSeen) {
		return false
	}
	return a.RetiredAt.IsZero() || t.Before(a.RetiredAt)
}

// retiredBefore reports whether the credential had already left the roster at t.
func (a *poolAccount) retiredBefore(t time.Time) bool {
	return !a.RetiredAt.IsZero() && !t.Before(a.RetiredAt)
}

// activeAt reports whether the credential belonged to the roster at t.
func (a *poolAccount) activeAt(t time.Time) bool {
	if a.FirstSeen.IsZero() {
		return false
	}
	if t.Before(a.FirstSeen) {
		return false
	}
	return !a.retiredBefore(t)
}

// poolLogEntry is one rendered pool log record. Request records carry the full
// correlation set; lifecycle records only carry a message.
type poolLogEntry struct {
	Timestamp     int64  `json:"ts"`
	Level         string `json:"lvl"`
	Message       string `json:"msg"`
	Source        string `json:"source,omitempty"`
	MappingStatus string `json:"mapping_status,omitempty"`
	LogType       int    `json:"log_type,omitempty"`
	RequestID     string `json:"rid,omitempty"`
	UpstreamID    string `json:"urid,omitempty"`
	AuthIndex     string `json:"ai,omitempty"`
	Account       string `json:"acct,omitempty"`
	Email         string `json:"email,omitempty"`
	Model         string `json:"model,omitempty"`
	Status        int    `json:"st,omitempty"`
	LatencyMS     int64  `json:"lat,omitempty"`
}

// Line renders the entry using the proxy log line format. The wall clock is the
// process timezone, matching internal/logging.LogFormatter, which formats
// entry.Time without converting to UTC. Request identifiers remain opaque.
func (e poolLogEntry) Line() string {
	timestamp := time.Unix(e.Timestamp, 0).Format("2006-01-02 15:04:05")
	source := strings.TrimSpace(e.Source)
	if source == "" {
		if e.RequestID == "" {
			source = "cpa"
		} else {
			source = "newapi"
		}
	}
	if e.RequestID == "" {
		return fmt.Sprintf("[%s] [%s] %s source=%s", timestamp, e.Level, e.Message, source)
	}
	line := fmt.Sprintf(
		"[%s] [%s] %s provider=claude account=%s email=%s auth_index=%s model=%s status=%d latency_ms=%d request_id=%q upstream_request_id=%q source=%s",
		timestamp, e.Level, e.Message, e.Account, e.Email, e.AuthIndex, e.Model, e.Status, e.LatencyMS, e.RequestID, e.UpstreamID, source,
	)
	if e.MappingStatus != "" {
		line += " mapping_status=" + e.MappingStatus
	}
	return line
}

// matches reports whether the entry satisfies a free-text query.
func (e poolLogEntry) matches(query string) bool {
	if query == "" {
		return true
	}
	for _, field := range []string{e.RequestID, e.UpstreamID, e.Account, e.Email, e.AuthIndex, e.Model, e.Message, e.Level, e.Source, e.MappingStatus} {
		if strings.Contains(strings.ToLower(field), query) {
			return true
		}
	}
	return false
}

// poolLogFilter constrains a log query.
type poolLogFilter struct {
	From      time.Time
	To        time.Time
	Level     string
	RequestID string
	Query     string
	Limit     int
}

type poolPersistentState struct {
	Version         int                           `json:"version"`
	Seed            int64                         `json:"seed"`
	Revision        uint64                        `json:"revision"`
	NextAccount     uint64                        `json:"next_account"`
	LastEpoch       int64                         `json:"last_epoch"`
	Accounts        []*poolAccount                `json:"accounts"`
	Retired         []*poolAccount                `json:"retired"`
	History         []poolLogAccount              `json:"history"`
	RequestMappings map[string]poolRequestMapping `json:"request_mappings,omitempty"`
	Events          []poolLogEntry                `json:"events"`
}

type poolSimulator struct {
	mu           sync.Mutex
	path         string
	state        poolPersistentState
	mappingDirty bool
}

func newPoolSimulator(path string, now time.Time, seed int64) *poolSimulator {
	simulator := &poolSimulator{path: strings.TrimSpace(path)}
	if simulator.load(now.UTC()) == nil {
		return simulator
	}
	if seed == 0 {
		seed = now.UTC().UnixNano()
	}
	now = now.UTC()
	simulator.state = poolPersistentState{
		Version:         poolStateVersion,
		Seed:            seed,
		LastEpoch:       now.Unix() / poolEpochSeconds,
		Accounts:        make([]*poolAccount, 0, poolInitialAccounts),
		Retired:         make([]*poolAccount, 0),
		History:         make([]poolLogAccount, 0),
		RequestMappings: make(map[string]poolRequestMapping),
		Events:          make([]poolLogEntry, 0, 256),
	}
	for len(simulator.state.Accounts) < poolInitialAccounts {
		account := simulator.newAccountLocked(now, false)
		if account.ID%61 == 0 {
			simulator.setTemporaryStatusLocked(account, "disabled", now.Add(45*time.Minute))
		} else if account.ID%43 == 0 {
			simulator.setTemporaryStatusLocked(account, "error", now.Add(30*time.Minute))
		}
		simulator.state.Accounts = append(simulator.state.Accounts, account)
	}
	simulator.assignHistoricalFirstSeenLocked(now)
	if errPersist := simulator.persistLocked(); errPersist != nil {
		log.WithError(errPersist).Warn("failed to persist initial credential pool state")
	}
	return simulator
}

func (s *poolSimulator) load(now time.Time) error {
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
	if errValidate := validatePoolPersistentState(&state); errValidate != nil {
		log.WithError(errValidate).Warn("credential pool state failed semantic validation; rebuilding")
		return errValidate
	}
	s.state = state
	migrated := false
	if s.state.RequestMappings == nil {
		s.state.RequestMappings = make(map[string]poolRequestMapping)
		migrated = true
	}
	// Only pre-history states (v1/v2) represent the founding generation whose
	// roster entry time must be backfilled once. Version 3 already records exact
	// FirstSeen values for later accounts and v3->v4 must preserve them.
	foundingState := state.Version < 3
	if state.Version < poolStateVersion {
		s.migrateLocked(now.UTC())
		migrated = true
	}
	if s.cleanupRetiredLocked(now.UTC()) {
		migrated = true
	}
	if s.cleanupHistoryLocked(now.UTC()) {
		migrated = true
	}
	if s.normalizeMaxPlansLocked() {
		migrated = true
	}
	if s.normalizeEventSourcesLocked() {
		migrated = true
	}
	if s.dropPersistedRequestEventsLocked() {
		migrated = true
	}
	if s.normalizeAccountBoundsLocked(now.UTC(), foundingState) {
		migrated = true
	}
	if migrated {
		// The decoded in-memory state is authoritative even if a migration write
		// fails (for example, during a transient disk-full condition). Rebuilding
		// here would silently replace the stable seed and every account identity.
		if errPersist := s.persistLocked(); errPersist != nil {
			log.WithError(errPersist).Warn("failed to persist migrated credential pool state; continuing with loaded identities")
		}
	}
	return nil
}

func validatePoolPersistentState(state *poolPersistentState) error {
	if state == nil || state.Seed == 0 || len(state.Accounts) == 0 {
		return fmt.Errorf("unsupported credential pool state")
	}
	if state.Version < 1 || state.Version > poolStateVersion {
		return fmt.Errorf("unsupported credential pool state version %d", state.Version)
	}
	seenIDs := make(map[uint64]struct{}, len(state.Accounts)+len(state.Retired))
	seenAuth := make(map[string]struct{}, len(state.Accounts)+len(state.Retired))
	seenEmail := make(map[string]struct{}, len(state.Accounts)+len(state.Retired))
	validateAccounts := func(label string, accounts []*poolAccount) error {
		for index, account := range accounts {
			if account == nil {
				return fmt.Errorf("%s account %d is null", label, index)
			}
			if errAccount := validatePoolIdentity(account.ID, account.AuthIndex, account.Email, account.Name); errAccount != nil {
				return fmt.Errorf("%s account %d: %w", label, index, errAccount)
			}
			if _, exists := seenIDs[account.ID]; exists {
				return fmt.Errorf("duplicate account id %d", account.ID)
			}
			if _, exists := seenAuth[account.AuthIndex]; exists {
				return fmt.Errorf("duplicate auth index %q", account.AuthIndex)
			}
			if _, exists := seenEmail[account.Email]; exists {
				return fmt.Errorf("duplicate masked email %q", account.Email)
			}
			for field, value := range map[string]string{
				"account": account.Account, "status": account.Status,
				"status_message": account.StatusMessage, "retired_reason": account.RetiredReason,
			} {
				if !safePoolStateText(value, 512) || containsUnmaskedGmail(value) {
					return fmt.Errorf("unsafe %s field", field)
				}
			}
			seenIDs[account.ID] = struct{}{}
			seenAuth[account.AuthIndex] = struct{}{}
			seenEmail[account.Email] = struct{}{}
		}
		return nil
	}
	if errAccounts := validateAccounts("current", state.Accounts); errAccounts != nil {
		return errAccounts
	}
	if errRetired := validateAccounts("retired", state.Retired); errRetired != nil {
		return errRetired
	}
	for index := range state.History {
		account := state.History[index]
		if errAccount := validatePoolIdentity(account.ID, account.AuthIndex, account.Email, account.Name); errAccount != nil {
			return fmt.Errorf("history account %d: %w", index, errAccount)
		}
		if containsUnmaskedGmail(account.Account) || containsUnmaskedGmail(account.StatusMessage) ||
			!safePoolStateText(account.Account, 512) || !safePoolStateText(account.StatusMessage, 512) {
			return fmt.Errorf("history account %d contains unsafe text", index)
		}
	}
	for index, event := range state.Events {
		if !safePoolStateText(event.Level, 16) || !safePoolStateText(event.Message, 2048) ||
			!safePoolStateText(event.Source, 16) || containsUnmaskedGmail(event.Message) {
			return fmt.Errorf("event %d contains unsafe text", index)
		}
	}
	if len(state.RequestMappings) > poolMaximumRequestMappings {
		return fmt.Errorf("too many persisted request mappings: %d", len(state.RequestMappings))
	}
	for requestID, mapping := range state.RequestMappings {
		if !validPoolRequestID(requestID) {
			return fmt.Errorf("request mapping contains invalid request ID")
		}
		if !safePoolIdentifier(mapping.AuthIndex, 128) || !strings.HasPrefix(mapping.AuthIndex, "claude-oauth-") {
			return fmt.Errorf("request mapping %q contains invalid auth index", requestID)
		}
		if mapping.RequestAt.IsZero() {
			return fmt.Errorf("request mapping %q has no source timestamp", requestID)
		}
		if errAccount := validatePoolIdentity(mapping.Account.ID, mapping.Account.AuthIndex, mapping.Account.Email, mapping.Account.Name); errAccount != nil {
			return fmt.Errorf("request mapping %q account: %w", requestID, errAccount)
		}
		if !safePoolStateText(mapping.Account.Account, 512) || !safePoolStateText(mapping.Account.Status, 32) ||
			!safePoolStateText(mapping.Account.StatusMessage, 512) || containsUnmaskedGmail(mapping.Account.Account) ||
			containsUnmaskedGmail(mapping.Account.StatusMessage) || mapping.Account.Plan != "Claude Max" {
			return fmt.Errorf("request mapping %q account contains unsafe text", requestID)
		}
		if mapping.Account.AuthIndex != mapping.AuthIndex || !mapping.Account.activeAt(mapping.RequestAt) {
			return fmt.Errorf("request mapping %q account snapshot is inconsistent", requestID)
		}
	}
	return nil
}

func validatePoolIdentity(id uint64, authIndex, email, name string) error {
	if id == 0 {
		return fmt.Errorf("zero account id")
	}
	if !strings.HasPrefix(authIndex, "claude-oauth-") || !safePoolIdentifier(authIndex, 128) {
		return fmt.Errorf("invalid auth index")
	}
	if !validMaskedPoolEmail(email) {
		return fmt.Errorf("invalid masked Gmail")
	}
	if name != "claude-"+email+".json" {
		return fmt.Errorf("credential name does not match masked Gmail")
	}
	return nil
}

func safePoolIdentifier(value string, maximum int) bool {
	if value == "" || len(value) > maximum {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' || character == '_' {
			continue
		}
		return false
	}
	return true
}

func safePoolStateText(value string, maximum int) bool {
	if len(value) > maximum {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func validMaskedPoolEmail(email string) bool {
	if len(email) > 128 || !strings.HasSuffix(email, "@gmail.com") || strings.Count(email, "@") != 1 {
		return false
	}
	local := strings.TrimSuffix(email, "@gmail.com")
	firstStar := strings.IndexByte(local, '*')
	if firstStar < 2 {
		return false
	}
	for _, character := range local[:firstStar] {
		if character < 'a' || character > 'z' {
			return false
		}
	}
	index := firstStar
	for index < len(local) && local[index] == '*' {
		index++
	}
	if index-firstStar < 3 || len(local)-index != 4 {
		return false
	}
	for _, character := range local[index:] {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func containsUnmaskedGmail(value string) bool {
	lower := strings.ToLower(value)
	const domain = "@gmail.com"
	for offset := 0; ; {
		index := strings.Index(lower[offset:], domain)
		if index < 0 {
			return false
		}
		index += offset
		start := index
		for start > 0 {
			character := lower[start-1]
			if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || strings.ContainsRune("._%+*-", rune(character)) {
				start--
				continue
			}
			break
		}
		if local := lower[start:index]; local != "" && !strings.Contains(local, "*") {
			return true
		}
		offset = index + len(domain)
	}
}

// migrateLocked upgrades older state in place while preserving credential
// identities. Version 2 introduced epoch-driven quotas, version 3 separates
// short-lived quota tombstones from the minimal log-correlation archive, and
// version 4 persists first-observed request-to-account associations.
func (s *poolSimulator) migrateLocked(now time.Time) {
	previousVersion := s.state.Version
	if previousVersion < 2 {
		s.state.Events = nil
		if s.state.LastEpoch == 0 {
			s.state.LastEpoch = now.Unix() / poolEpochSeconds
		}
		for _, accounts := range [][]*poolAccount{s.state.Accounts, s.state.Retired} {
			for _, account := range accounts {
				account.FiveHour.RatePerMinute = s.quotaRateLocked(account.ID, "five", 0.06, 0.22)
				account.SevenDay.RatePerMinute = s.quotaRateLocked(account.ID, "seven", 0.0040, 0.0110)
				account.SevenDayOAuthApps.RatePerMinute = s.quotaRateLocked(account.ID, "oauth", 0.0020, 0.0070)
				account.SevenDayOpus.RatePerMinute = s.quotaRateLocked(account.ID, "opus", 0.0025, 0.0080)
				account.SevenDaySonnet.RatePerMinute = s.quotaRateLocked(account.ID, "sonnet", 0.0030, 0.0090)
				account.SevenDayCowork.RatePerMinute = s.quotaRateLocked(account.ID, "cowork", 0.0015, 0.0055)
			}
		}
		s.assignHistoricalFirstSeenLocked(now)
	}
	if previousVersion < 3 {
		// Every account that existed before the history-aware state version belongs
		// to the founding generation. Backdate it once to the retention boundary so
		// all retained New API logs have a non-empty historical roster.
		s.assignHistoricalFirstSeenLocked(now)
		for _, account := range s.state.Retired {
			s.archiveAccountLocked(account)
		}
	}
	if previousVersion < 4 || s.state.RequestMappings == nil {
		s.state.RequestMappings = make(map[string]poolRequestMapping)
	}
	s.state.Version = poolStateVersion
}

// assignHistoricalFirstSeenLocked marks all pre-v3 credentials as the founding
// generation. Later credentials are created with exact FirstSeen timestamps and
// therefore skip this one-time migration.
func (s *poolSimulator) assignHistoricalFirstSeenLocked(now time.Time) {
	accounts := make([]*poolAccount, 0, len(s.state.Accounts)+len(s.state.Retired))
	accounts = append(accounts, s.state.Accounts...)
	accounts = append(accounts, s.state.Retired...)
	foundingAt := now.UTC().Add(-poolHistoryWindow).Truncate(time.Second)
	for _, account := range accounts {
		if account.FirstSeen.IsZero() || account.FirstSeen.After(foundingAt) {
			account.FirstSeen = foundingAt
		}
		if account.CreatedAt.IsZero() || account.CreatedAt.After(foundingAt) {
			account.CreatedAt = foundingAt
		}
	}
}

func (s *poolSimulator) normalizeMaxPlansLocked() bool {
	changed := false
	for _, accounts := range [][]*poolAccount{s.state.Accounts, s.state.Retired} {
		for _, account := range accounts {
			if account.Plan != "Claude Max" {
				account.Plan = "Claude Max"
				changed = true
			}
		}
	}
	for index := range s.state.History {
		if s.state.History[index].Plan != "Claude Max" {
			s.state.History[index].Plan = "Claude Max"
			changed = true
		}
	}
	return changed
}

func (s *poolSimulator) normalizeEventSourcesLocked() bool {
	changed := false
	for index := range s.state.Events {
		if strings.TrimSpace(s.state.Events[index].Source) == "" {
			s.state.Events[index].Source = "cpa"
			changed = true
		}
	}
	return changed
}

// dropPersistedRequestEventsLocked removes request-shaped records written by
// older synthetic log implementations. Real New API requests live exclusively
// in the separate bounded log cache and are never persisted in pool-state.json.
func (s *poolSimulator) dropPersistedRequestEventsLocked() bool {
	retained := s.state.Events[:0]
	for _, event := range s.state.Events {
		if event.RequestID != "" || event.UpstreamID != "" || event.Source == "newapi" {
			continue
		}
		retained = append(retained, event)
	}
	changed := len(retained) != len(s.state.Events)
	s.state.Events = retained
	return changed
}

// normalizeAccountBoundsLocked repairs legacy or interrupted states without
// discarding their stable seed and identities. Semantic identity corruption is
// rejected before this method is called.
func (s *poolSimulator) normalizeAccountBoundsLocked(now time.Time, founding bool) bool {
	changed := false
	maximumID := s.state.NextAccount
	for _, account := range s.state.Accounts {
		if account.ID > maximumID {
			maximumID = account.ID
		}
	}
	for _, account := range s.state.Retired {
		if account.ID > maximumID {
			maximumID = account.ID
		}
	}
	for _, account := range s.state.History {
		if account.ID > maximumID {
			maximumID = account.ID
		}
	}
	if s.state.NextAccount != maximumID {
		s.state.NextAccount = maximumID
		changed = true
	}
	if s.state.LastEpoch == 0 {
		s.state.LastEpoch = now.UTC().Unix() / poolEpochSeconds
		changed = true
	}
	if len(s.state.Accounts) > poolMaximumAccounts {
		excess := append([]*poolAccount(nil), s.state.Accounts[poolMaximumAccounts:]...)
		s.state.Accounts = s.state.Accounts[:poolMaximumAccounts]
		for _, account := range excess {
			s.retireLocked(account, now.UTC(), "state bound repair")
		}
		changed = true
	}
	for len(s.state.Accounts) < poolMinimumAccounts {
		s.state.Accounts = append(s.state.Accounts, s.newAccountLocked(now.UTC(), !founding))
		changed = true
	}
	if founding {
		s.assignHistoricalFirstSeenLocked(now.UTC())
	}
	return changed
}

func (s *poolSimulator) persistLocked() error {
	if s.path == "" {
		s.mappingDirty = false
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
			if errRemove := os.Remove(temporaryName); errRemove != nil && !os.IsNotExist(errRemove) {
				log.WithError(errRemove).Warn("failed to remove temporary credential pool state")
			}
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
	s.mappingDirty = false
	return nil
}

// poolFloatFromParts derives a deterministic float in [0,1) from a seed and salt.
func poolFloatFromParts(seed int64, salt string, discriminator int64) float64 {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%d|%s|%d", seed, salt, discriminator)))
	return float64(binary.BigEndian.Uint64(sum[:8])>>11) / float64(uint64(1)<<53)
}

// randomLocked derives a deterministic float in [0,1) for the current epoch.
func (s *poolSimulator) randomLocked(salt string) float64 {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%d|%d|%s", s.state.Seed, s.state.LastEpoch, salt)))
	return float64(binary.BigEndian.Uint64(sum[:8])>>11) / float64(uint64(1)<<53)
}

// randomAtLocked derives a deterministic float in [0,1) for an explicit epoch.
func (s *poolSimulator) randomAtLocked(epoch int64, salt string) float64 {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%d|%d|%s", s.state.Seed, epoch, salt)))
	return float64(binary.BigEndian.Uint64(sum[:8])>>11) / float64(uint64(1)<<53)
}

func (s *poolSimulator) quotaRateLocked(id uint64, salt string, low, high float64) float64 {
	return low + poolFloatFromParts(s.state.Seed, "rate-"+salt, int64(id))*(high-low)
}

func (s *poolSimulator) authFiles(now time.Time, advance bool) []gin.H {
	s.mu.Lock()
	defer s.mu.Unlock()
	now = now.UTC()
	if advance {
		if s.advanceLocked(now) {
			if errPersist := s.persistLocked(); errPersist != nil {
				log.WithError(errPersist).Warn("failed to persist credential pool state")
			}
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

// advanceLocked steps the simulation forward to the epoch containing now.
// It is idempotent within an epoch, so request volume never drives evolution.
func (s *poolSimulator) advanceLocked(now time.Time) bool {
	target := now.Unix() / poolEpochSeconds
	if s.state.LastEpoch <= 0 {
		s.state.LastEpoch = target
		return false
	}
	if target <= s.state.LastEpoch {
		return false
	}
	if target-s.state.LastEpoch > poolMaxCatchUpEpochs {
		s.state.LastEpoch = target - poolMaxCatchUpEpochs
	}
	for epoch := s.state.LastEpoch + 1; epoch <= target; epoch++ {
		s.state.LastEpoch = epoch
		s.stepEpochLocked(epoch)
	}
	s.state.LastEpoch = target
	s.state.Revision++
	return true
}

// stepEpochLocked applies one simulation epoch.
func (s *poolSimulator) stepEpochLocked(epoch int64) {
	now := time.Unix(epoch*poolEpochSeconds, 0).UTC()
	s.cleanupRetiredLocked(now)
	s.cleanupHistoryLocked(now)

	for _, account := range s.state.Accounts {
		s.applyElapsedLocked(account, now)
		switch {
		case s.accountExhaustedLocked(account):
			// Quota exhaustion is temporary: the credential recovers when its
			// window resets, matching real Claude Max behaviour.
			if account.StatusMessage != "Quota exhausted" {
				account.Status = "error"
				account.StatusMessage = "Quota exhausted"
				account.Unavailable = true
				account.Disabled = false
				account.StatusUntil = time.Time{}
				s.appendEventLocked(now, "WARN", fmt.Sprintf(
					"quota exhausted provider=claude account=%s email=%s auth_index=%s",
					account.Name, account.Email, account.AuthIndex))
			}
		case account.StatusMessage == "Quota exhausted":
			s.setActiveLocked(account)
			s.appendEventLocked(now, "INFO", fmt.Sprintf(
				"credential restored provider=claude account=%s email=%s auth_index=%s",
				account.Name, account.Email, account.AuthIndex))
		case account.Status != "active" && !account.StatusUntil.IsZero() && !now.Before(account.StatusUntil):
			s.setActiveLocked(account)
			s.appendEventLocked(now, "INFO", fmt.Sprintf(
				"credential restored provider=claude account=%s email=%s auth_index=%s",
				account.Name, account.Email, account.AuthIndex))
		}
	}

	s.reconcileStatusesLocked(now, epoch)
	s.applyPermanentFailureLocked(now, epoch)
	s.adjustPopulationLocked(now, epoch)
	s.trimEventsLocked(now)
}

// applyPermanentFailureLocked retires a credential outright on rare occasions,
// approximating roughly one or two permanent revocations per week.
func (s *poolSimulator) applyPermanentFailureLocked(now time.Time, epoch int64) {
	if len(s.state.Accounts) <= poolMinimumAccounts {
		return
	}
	if s.randomAtLocked(epoch, "permanent-failure") >= 0.00074 {
		return
	}
	index := int(s.randomAtLocked(epoch, "permanent-pick") * float64(len(s.state.Accounts)))
	if index >= len(s.state.Accounts) {
		index = len(s.state.Accounts) - 1
	}
	account := s.state.Accounts[index]
	s.retireLocked(account, now, "credential revoked upstream")
	s.state.Accounts = append(s.state.Accounts[:index], s.state.Accounts[index+1:]...)
}

// adjustPopulationLocked drifts the roster size every six hours. The drift is
// mean-reverting toward the nominal size so churn stays low enough that the
// full retention window of credentials remains listable.
func (s *poolSimulator) adjustPopulationLocked(now time.Time, epoch int64) {
	const stepEpochs = 72 // six hours
	if epoch%stepEpochs != 0 {
		return
	}
	current := len(s.state.Accounts)
	nominal := (poolMinimumAccounts + poolMaximumAccounts) / 2
	delta := int(s.randomAtLocked(epoch, "population-delta") * 3)
	if delta == 0 {
		return
	}
	bias := 0.5
	switch {
	case current > nominal:
		bias = 0.25
	case current < nominal:
		bias = 0.75
	}
	if s.randomAtLocked(epoch, "population-direction") >= bias {
		delta = -delta
	}
	target := current + delta
	if target < poolMinimumAccounts {
		target = poolMinimumAccounts
	}
	if target > poolMaximumAccounts {
		target = poolMaximumAccounts
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
		s.appendEventLocked(now, "INFO", fmt.Sprintf(
			"credential registered provider=claude account=%s email=%s auth_index=%s plan=%s",
			account.Name, account.Email, account.AuthIndex, account.Plan))
	}
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
	// Counters track the share of pool traffic this credential absorbed.
	served := poolMeanRPM() * minutes / math.Max(1, float64(len(s.state.Accounts)))
	account.Success += int64(served)
	if account.Status != "active" {
		account.Failed += int64(served * 0.01)
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
		window.Utilization = poolFloatFromParts(s.state.Seed, "reset-"+salt, int64(account.ID)+window.ResetAt.Unix()) * 3
	}
	jitter := 0.6 + poolFloatFromParts(s.state.Seed, "jitter-"+salt, int64(account.ID)+now.Unix()/poolEpochSeconds)*0.8
	window.Utilization = clampPoolUtilization(window.Utilization + minutes*window.RatePerMinute*jitter)
}

func (s *poolSimulator) accountExhaustedLocked(account *poolAccount) bool {
	return account.FiveHour.Utilization >= 100 || account.SevenDay.Utilization >= 100
}

func (s *poolSimulator) reconcileStatusesLocked(now time.Time, epoch int64) {
	abnormal := 0
	active := make([]*poolAccount, 0, len(s.state.Accounts))
	for _, account := range s.state.Accounts {
		if account.Status == "active" {
			active = append(active, account)
		} else {
			abnormal++
		}
	}
	target := int(math.Ceil(float64(len(s.state.Accounts)) * (0.02 + s.randomAtLocked(epoch, "abnormal-target")*0.04)))
	changes := int(s.randomAtLocked(epoch, "abnormal-changes") * 2)
	for abnormal < target && len(active) > 0 && changes > 0 {
		index := int(s.randomAtLocked(epoch, fmt.Sprintf("abnormal-pick-%d", changes)) * float64(len(active)))
		if index >= len(active) {
			index = len(active) - 1
		}
		account := active[index]
		status := "error"
		if s.randomAtLocked(epoch, fmt.Sprintf("abnormal-kind-%d", account.ID)) < 0.35 {
			status = "disabled"
		}
		duration := time.Duration(30+int(s.randomAtLocked(epoch, fmt.Sprintf("abnormal-duration-%d", account.ID))*90)) * time.Minute
		s.setTemporaryStatusLocked(account, status, now.Add(duration))
		s.appendEventLocked(now, "WARN", fmt.Sprintf(
			"credential %s provider=claude account=%s email=%s auth_index=%s",
			status, account.Name, account.Email, account.AuthIndex))
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
	account.RetiredReason = reason
	account.Status = "disabled"
	account.StatusMessage = "Credential retired"
	account.Disabled = true
	account.Unavailable = false
	account.StatusUntil = time.Time{}
	s.archiveAccountLocked(account)
	s.state.Retired = append(s.state.Retired, account)
	s.appendEventLocked(now, "INFO", fmt.Sprintf(
		"credential removed provider=claude account=%s email=%s auth_index=%s reason=%q",
		account.Name, account.Email, account.AuthIndex, reason))
}

func (s *poolSimulator) cleanupRetiredLocked(now time.Time) bool {
	cutoff := now.Add(-poolRetiredGracePeriod)
	retained := s.state.Retired[:0]
	for _, account := range s.state.Retired {
		if account.RetiredAt.IsZero() || !account.RetiredAt.Before(cutoff) {
			retained = append(retained, account)
		}
	}
	changed := len(retained) != len(s.state.Retired)
	s.state.Retired = retained
	return changed
}

// archiveAccountLocked upserts the compact, credential-free snapshot needed to
// resolve the presentation account associated with a historical request.
func (s *poolSimulator) archiveAccountLocked(account *poolAccount) {
	identity := newPoolLogAccount(account)
	if identity.AuthIndex == "" || identity.RetiredAt.IsZero() {
		return
	}
	for index := range s.state.History {
		if s.state.History[index].AuthIndex == identity.AuthIndex {
			s.state.History[index] = identity
			return
		}
	}
	s.state.History = append(s.state.History, identity)
}

func (s *poolSimulator) cleanupHistoryLocked(now time.Time) bool {
	cutoff := now.Add(-poolHistoryWindow)
	changed := s.trimRequestMappingsLocked(now)
	retained := s.state.History[:0]
	for _, account := range s.state.History {
		if account.RetiredAt.IsZero() || !account.RetiredAt.Before(cutoff) {
			retained = append(retained, account)
		}
	}
	changed = changed || len(retained) != len(s.state.History)
	s.state.History = retained
	return changed
}

func (s *poolSimulator) trimRequestMappingsLocked(now time.Time) bool {
	changed := false
	cutoff := now.UTC().Add(-poolHistoryWindow)
	for requestID, mapping := range s.state.RequestMappings {
		if mapping.RequestAt.Before(cutoff) {
			delete(s.state.RequestMappings, requestID)
			changed = true
		}
	}
	if len(s.state.RequestMappings) <= poolMaximumRequestMappings {
		if changed {
			s.mappingDirty = true
		}
		return changed
	}
	type mappingAge struct {
		requestID string
		requestAt time.Time
	}
	ordered := make([]mappingAge, 0, len(s.state.RequestMappings))
	for requestID, mapping := range s.state.RequestMappings {
		ordered = append(ordered, mappingAge{requestID: requestID, requestAt: mapping.RequestAt})
	}
	sort.Slice(ordered, func(i, j int) bool {
		if !ordered[i].requestAt.Equal(ordered[j].requestAt) {
			return ordered[i].requestAt.Before(ordered[j].requestAt)
		}
		return ordered[i].requestID < ordered[j].requestID
	})
	for _, candidate := range ordered[:len(ordered)-poolMaximumRequestMappings] {
		delete(s.state.RequestMappings, candidate.requestID)
	}
	s.mappingDirty = true
	return true
}

// rosterAtTime returns an immutable, auth-index-sorted snapshot of the credentials that
// belonged to the pool at the supplied instant. It is safe for concurrent log
// ingestion and query code to retain the returned slice.
func (s *poolSimulator) rosterAtTime(at time.Time) []poolLogAccount {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rosterAtTimeLocked(at.UTC())
}

func (s *poolSimulator) rosterAtTimeLocked(at time.Time) []poolLogAccount {
	byID := make(map[uint64]poolLogAccount, len(s.state.Accounts)+len(s.state.Retired)+len(s.state.History))
	for _, archived := range s.state.History {
		if archived.activeAt(at) {
			byID[archived.ID] = archived
		}
	}
	for _, accounts := range [][]*poolAccount{s.state.Retired, s.state.Accounts} {
		for _, account := range accounts {
			identity := newPoolLogAccount(account)
			if identity.activeAt(at) {
				byID[identity.ID] = identity
			}
		}
	}
	roster := make([]poolLogAccount, 0, len(byID))
	for _, account := range byID {
		roster = append(roster, account)
	}
	sort.Slice(roster, func(i, j int) bool {
		return roster[i].AuthIndex < roster[j].AuthIndex
	})
	return roster
}

// mapRequestAccount deterministically assigns an opaque upstream request ID to
// a credential that was active when the request occurred. The seed, ordering
// and historical roster are persisted, so the mapping survives reloads and
// later pool churn.
func (s *poolSimulator) mapRequestAccount(at time.Time, requestID string) (poolLogAccount, bool) {
	if requestID == "" {
		return poolLogAccount{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	account, found, created := s.mapRequestAccountLocked(at.UTC(), requestID)
	if created {
		s.trimRequestMappingsLocked(at.UTC())
	}
	if s.mappingDirty {
		if errPersist := s.persistLocked(); errPersist != nil {
			log.WithError(errPersist).Warn("failed to persist request-to-account mapping")
		}
	}
	return account, found
}

func (s *poolSimulator) mapRequestAccountLocked(at time.Time, requestID string) (poolLogAccount, bool, bool) {
	if requestID == "" {
		return poolLogAccount{}, false, false
	}
	if mapping, exists := s.state.RequestMappings[requestID]; exists {
		return s.resolveRequestMappingLocked(mapping), true, false
	}
	roster, projected := s.mappingRosterAtTimeLocked(at.UTC())
	if !projected {
		return poolLogAccount{}, false, false
	}
	return s.pinRequestAccountLocked(at.UTC(), requestID, roster)
}

// mappingRosterAtTimeLocked returns the roster from the state that would exist
// after an auth-files refresh at at. When lifecycle epochs have not yet been
// materialized, it advances a deep in-memory clone and never mutates live pool
// quotas, counters, events, revision or LastEpoch.
func (s *poolSimulator) mappingRosterAtTimeLocked(at time.Time) ([]poolLogAccount, bool) {
	if at.Unix()/poolEpochSeconds <= s.state.LastEpoch {
		return s.rosterAtTimeLocked(at), true
	}
	// Request pins and rendered lifecycle events do not participate in pool
	// evolution. Excluding them keeps each epoch projection bounded by the small
	// credential roster even when the 20,000-entry mapping cache is full.
	projectedBase := s.state
	projectedBase.RequestMappings = nil
	projectedBase.Events = nil
	encoded, errEncode := json.Marshal(&projectedBase)
	if errEncode != nil {
		log.WithError(errEncode).Warn("failed to clone credential pool for request mapping")
		return nil, false
	}
	var projectedState poolPersistentState
	if errDecode := json.Unmarshal(encoded, &projectedState); errDecode != nil {
		log.WithError(errDecode).Warn("failed to decode credential pool mapping projection")
		return nil, false
	}
	projection := &poolSimulator{state: projectedState}
	projection.advanceLocked(at.UTC())
	return projection.rosterAtTimeLocked(at.UTC()), true
}

func (s *poolSimulator) pinRequestAccountLocked(at time.Time, requestID string, roster []poolLogAccount) (poolLogAccount, bool, bool) {
	if mapping, exists := s.state.RequestMappings[requestID]; exists {
		return s.resolveRequestMappingLocked(mapping), true, false
	}
	if len(roster) == 0 {
		return poolLogAccount{}, false, false
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("%d|newapi-v1|%s", s.state.Seed, requestID)))
	index := binary.BigEndian.Uint64(sum[:8]) % uint64(len(roster))
	account := roster[index]
	if s.state.RequestMappings == nil {
		s.state.RequestMappings = make(map[string]poolRequestMapping)
	}
	s.state.RequestMappings[requestID] = poolRequestMapping{
		AuthIndex: account.AuthIndex,
		RequestAt: at.UTC(),
		Account:   account,
	}
	s.mappingDirty = true
	return account, true, true
}

func (s *poolSimulator) resolveRequestMappingLocked(mapping poolRequestMapping) poolLogAccount {
	if account, found := s.logAccountByAuthIndexLocked(mapping.AuthIndex); found {
		return account
	}
	return mapping.Account
}

func (s *poolSimulator) logAccountByAuthIndexLocked(authIndex string) (poolLogAccount, bool) {
	for _, account := range s.state.Accounts {
		if account.AuthIndex == authIndex {
			return newPoolLogAccount(account), true
		}
	}
	for _, account := range s.state.Retired {
		if account.AuthIndex == authIndex {
			return newPoolLogAccount(account), true
		}
	}
	for _, account := range s.state.History {
		if account.AuthIndex == authIndex {
			return account, true
		}
	}
	return poolLogAccount{}, false
}

// logAccountByAuthIndex resolves a current or recently archived credential for
// log-detail views without exposing the mutable quota record.
func (s *poolSimulator) logAccountByAuthIndex(now time.Time, authIndex string) (poolLogAccount, bool) {
	authIndex = strings.TrimSpace(authIndex)
	if authIndex == "" {
		return poolLogAccount{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := now.UTC().Add(-poolHistoryWindow)
	account, found := s.logAccountByAuthIndexLocked(authIndex)
	if found {
		if !account.RetiredAt.IsZero() && account.RetiredAt.Before(cutoff) {
			return poolLogAccount{}, false
		}
		return account, true
	}
	for _, mapping := range s.state.RequestMappings {
		if mapping.AuthIndex == authIndex && !mapping.RequestAt.Before(cutoff) {
			return mapping.Account, true
		}
	}
	return poolLogAccount{}, false
}

func (s *poolSimulator) trimEventsLocked(now time.Time) {
	cutoff := now.Add(-poolEventRetention).Unix()
	retained := s.state.Events[:0]
	for _, event := range s.state.Events {
		if event.Timestamp >= cutoff {
			retained = append(retained, event)
		}
	}
	if len(retained) > poolMaximumEvents {
		retained = append([]poolLogEntry(nil), retained[len(retained)-poolMaximumEvents:]...)
	}
	s.state.Events = retained
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
	createdAt := now.Add(-time.Duration(20+int(poolFloatFromParts(s.state.Seed, "age", int64(id))*2400)) * time.Minute)
	if fresh {
		createdAt = now
	}
	email := s.maskedEmailLocked(id)
	authHash := sha256.Sum256([]byte(fmt.Sprintf("%d:%d", s.state.Seed, id)))
	authIndex := fmt.Sprintf("claude-oauth-%x", authHash[:10])
	initial := func(salt string) float64 {
		if fresh {
			return poolFloatFromParts(s.state.Seed, "fresh-"+salt, int64(id)) * 3
		}
		return 3 + poolFloatFromParts(s.state.Seed, "initial-"+salt, int64(id))*80
	}
	monthlyLimit := 20000
	if id%5 == 0 {
		monthlyLimit = 50000
	}
	firstSeen := time.Time{}
	if fresh {
		// FirstSeen and CreatedAt are the exact instant the credential joined this
		// pool and must never be backdated because historical request-to-account
		// mappings depend on them.
		firstSeen = now
	}
	return &poolAccount{
		ID:                id,
		AuthIndex:         authIndex,
		Email:             email,
		Name:              fmt.Sprintf("claude-%s.json", email),
		Plan:              "Claude Max",
		Account:           fmt.Sprintf("user_%012x", 0x4a3c10000000+id*104729),
		Status:            "active",
		FirstSeen:         firstSeen,
		CreatedAt:         createdAt,
		UpdatedAt:         now,
		LastRefresh:       now,
		Success:           int64(320 + (id*137)%8900),
		Failed:            int64(id % 3),
		Priority:          int((id - 1) % 5),
		FiveHour:          poolQuotaWindow{Utilization: initial("five"), RatePerMinute: s.quotaRateLocked(id, "five", 0.06, 0.22), ResetAt: now.Add(5 * time.Hour)},
		SevenDay:          poolQuotaWindow{Utilization: initial("seven"), RatePerMinute: s.quotaRateLocked(id, "seven", 0.0040, 0.0110), ResetAt: now.Add(7 * 24 * time.Hour)},
		SevenDayOAuthApps: poolQuotaWindow{Utilization: initial("oauth"), RatePerMinute: s.quotaRateLocked(id, "oauth", 0.0020, 0.0070), ResetAt: now.Add(7 * 24 * time.Hour)},
		SevenDayOpus:      poolQuotaWindow{Utilization: initial("opus"), RatePerMinute: s.quotaRateLocked(id, "opus", 0.0025, 0.0080), ResetAt: now.Add(7 * 24 * time.Hour)},
		SevenDaySonnet:    poolQuotaWindow{Utilization: initial("sonnet"), RatePerMinute: s.quotaRateLocked(id, "sonnet", 0.0030, 0.0090), ResetAt: now.Add(7 * 24 * time.Hour)},
		SevenDayCowork:    poolQuotaWindow{Utilization: initial("cowork"), RatePerMinute: s.quotaRateLocked(id, "cowork", 0.0015, 0.0055), ResetAt: now.Add(7 * 24 * time.Hour)},
		ExtraUsageEnabled: id%4 != 0,
		ExtraUsedCredits:  850 + int((id*739)%14200),
		ExtraMonthlyLimit: monthlyLimit,
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

// recentRequestsLocked builds the twenty ten-minute buckets the panel charts,
// using the same label format as the live credential manager.
func (s *poolSimulator) recentRequestsLocked(account *poolAccount, now time.Time) []gin.H {
	anchor := now.UTC().Truncate(10 * time.Minute)
	accounts := math.Max(1, float64(len(s.state.Accounts)))
	buckets := make([]gin.H, 0, 20)
	for i := 19; i >= 0; i-- {
		start := anchor.Add(-time.Duration(i) * 10 * time.Minute)
		end := start.Add(10 * time.Minute)
		success := int64(0)
		failed := int64(0)
		if account.activeAt(start) {
			share := poolRPMAt(start) * 10 / accounts
			jitter := 0.6 + poolFloatFromParts(s.state.Seed, "bucket", int64(account.ID)+start.Unix())*0.8
			success = int64(share * jitter)
			if success > 0 && poolFloatFromParts(s.state.Seed, "bucket-fail", int64(account.ID)+start.Unix()) < 0.2 {
				failed = 1 + int64(float64(success)*0.01)
			}
		}
		buckets = append(buckets, gin.H{
			"time":    fmt.Sprintf("%s-%s", start.Format("15:04"), end.Format("15:04")),
			"success": success,
			"failed":  failed,
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
	now = now.UTC()
	account := s.findQuotaAccountLocked(authIndex, now)
	if account == nil {
		return nil, false
	}
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

func (s *poolSimulator) profile(now time.Time, authIndex string) (gin.H, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	account := s.findQuotaAccountLocked(authIndex, now.UTC())
	if account == nil {
		return nil, false
	}
	profileAccount := gin.H{
		"uuid":           fmt.Sprintf("%08x-%04x-4%03x-8%03x-%012x", account.ID*104729, account.ID, account.ID%4096, account.ID%4096, account.ID*99991),
		"has_claude_max": true,
		"has_claude_pro": false,
	}
	return gin.H{"account": profileAccount}, true
}

func (s *poolSimulator) findAccountLocked(authIndex string) *poolAccount {
	return s.findQuotaAccountLocked(authIndex, time.Now().UTC())
}

func (s *poolSimulator) findQuotaAccountLocked(authIndex string, now time.Time) *poolAccount {
	for _, account := range s.state.Accounts {
		if account.AuthIndex == authIndex {
			return account
		}
	}
	cutoff := now.Add(-poolRetiredGracePeriod)
	for _, account := range s.state.Retired {
		if account.AuthIndex == authIndex && (account.RetiredAt.IsZero() || !account.RetiredAt.Before(cutoff)) {
			return account
		}
	}
	return nil
}

func (s *poolSimulator) appendEventLocked(timestamp time.Time, level, message string) {
	s.state.Events = append(s.state.Events, poolLogEntry{
		Timestamp: timestamp.UTC().Unix(),
		Level:     level,
		Message:   message,
		Source:    "cpa",
	})
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
