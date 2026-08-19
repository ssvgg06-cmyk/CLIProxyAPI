package management

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	log "github.com/sirupsen/logrus"
)

const (
	poolLogSourceURLEnvironment       = "CPA_POOL_LOG_SOURCE_URL"
	poolLogSourceTokenFileEnvironment = "CPA_POOL_LOG_SOURCE_TOKEN_FILE"
	poolLogCachePathEnvironment       = "CPA_POOL_LOG_CACHE_PATH"

	poolLogPollInterval    = 5 * time.Second
	poolLogPersistInterval = time.Minute
	poolLogSourceTimeout   = 10 * time.Second
	poolLogSourcePageSize  = 1000
	poolLogSourceMaxPages  = 20
	poolLogSourceMaxBody   = 8 << 20
	poolLogFreshnessWindow = 3 * poolLogPollInterval
	poolLogPrimeWindow     = 30 * time.Minute
)

var (
	errPoolLogSourceUnavailable   = errors.New("New API log source unavailable")
	errPoolLogSourceNotConfigured = errors.New("New API log source is not configured")
)

type poolLogSourcePage struct {
	Items        []poolSourceLog
	NextAfterID  int64
	NextBeforeID int64
	HasMore      bool
}

type poolLogSource interface {
	Changes(ctx context.Context, afterID int64, limit int) (poolLogSourcePage, error)
	Search(ctx context.Context, from, to time.Time, beforeID int64, limit int) (poolLogSourcePage, error)
	Lookup(ctx context.Context, requestID string) (poolLogSourcePage, error)
}

type bridgePoolLogSource struct {
	baseURL *url.URL
	token   string
	client  *http.Client
}

type bridgePoolLogResponse struct {
	Items        []poolSourceLog `json:"items"`
	NextAfterID  int64           `json:"next_after_id"`
	NextBeforeID int64           `json:"next_before_id"`
	HasMore      bool            `json:"has_more"`
}

func newBridgePoolLogSource(rawURL, token string, client *http.Client) (*bridgePoolLogSource, error) {
	parsed, errParse := url.Parse(strings.TrimSpace(rawURL))
	if errParse != nil {
		return nil, fmt.Errorf("parse New API log source URL: %w", errParse)
	}
	if parsed.Scheme != "https" && (parsed.Scheme != "http" || !poolLogSourceLoopback(parsed.Hostname())) {
		return nil, errors.New("New API log source URL must use HTTPS; HTTP is allowed only on loopback")
	}
	if parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("New API log source URL must be an origin or path without credentials, query, or fragment")
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, errors.New("New API log source token is empty")
	}
	if client == nil {
		client = &http.Client{Timeout: poolLogSourceTimeout}
	}
	clientCopy := *client
	// Do not follow redirects with a bearer credential. Keeping every request on
	// the configured origin also prevents an HTTPS endpoint from redirecting the
	// token to cleartext HTTP or to a different host.
	clientCopy.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &bridgePoolLogSource{baseURL: parsed, token: token, client: &clientCopy}, nil
}

func poolLogSourceLoopback(host string) bool {
	if strings.EqualFold(strings.TrimSpace(host), "localhost") {
		return true
	}
	address := net.ParseIP(strings.TrimSpace(host))
	return address != nil && address.IsLoopback()
}

func (s *bridgePoolLogSource) Changes(ctx context.Context, afterID int64, limit int) (poolLogSourcePage, error) {
	values := url.Values{}
	if afterID > 0 {
		values.Set("after_id", strconv.FormatInt(afterID, 10))
	}
	values.Set("limit", strconv.Itoa(clampPoolLogSourceLimit(limit)))
	return s.get(ctx, "v1/logs/changes", values)
}

func (s *bridgePoolLogSource) Search(ctx context.Context, from, to time.Time, beforeID int64, limit int) (poolLogSourcePage, error) {
	values := url.Values{}
	if !from.IsZero() {
		values.Set("from", strconv.FormatInt(from.UTC().Unix(), 10))
	}
	if !to.IsZero() {
		values.Set("to", strconv.FormatInt(to.UTC().Unix(), 10))
	}
	if beforeID > 0 {
		values.Set("before_id", strconv.FormatInt(beforeID, 10))
	}
	values.Set("limit", strconv.Itoa(clampPoolLogSourceLimit(limit)))
	return s.get(ctx, "v1/logs/search", values)
}

func (s *bridgePoolLogSource) Lookup(ctx context.Context, requestID string) (poolLogSourcePage, error) {
	if !validPoolRequestID(requestID) {
		return poolLogSourcePage{}, errors.New("invalid request ID")
	}
	values := url.Values{"request_id": []string{requestID}}
	return s.get(ctx, "v1/logs/lookup", values)
}

func (s *bridgePoolLogSource) get(ctx context.Context, endpoint string, values url.Values) (poolLogSourcePage, error) {
	if s == nil || s.baseURL == nil || s.client == nil {
		return poolLogSourcePage{}, errPoolLogSourceUnavailable
	}
	target, errJoin := url.JoinPath(s.baseURL.String(), endpoint)
	if errJoin != nil {
		return poolLogSourcePage{}, fmt.Errorf("build New API log source URL: %w", errJoin)
	}
	parsed, errParse := url.Parse(target)
	if errParse != nil {
		return poolLogSourcePage{}, fmt.Errorf("parse New API log source endpoint: %w", errParse)
	}
	parsed.RawQuery = values.Encode()
	request, errRequest := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if errRequest != nil {
		return poolLogSourcePage{}, fmt.Errorf("create New API log source request: %w", errRequest)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+s.token)
	request.Header.Set("User-Agent", "cpa-pool-log-source/1")

	response, errDo := s.client.Do(request)
	if errDo != nil {
		return poolLogSourcePage{}, fmt.Errorf("query New API log source: %w", errDo)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return poolLogSourcePage{}, fmt.Errorf("query New API log source: HTTP %d", response.StatusCode)
	}

	body, errRead := io.ReadAll(io.LimitReader(response.Body, poolLogSourceMaxBody+1))
	if errRead != nil {
		return poolLogSourcePage{}, fmt.Errorf("read New API log source response: %w", errRead)
	}
	if len(body) > poolLogSourceMaxBody {
		return poolLogSourcePage{}, errors.New("New API log source response is too large")
	}
	var payload bridgePoolLogResponse
	if errDecode := json.Unmarshal(body, &payload); errDecode != nil {
		return poolLogSourcePage{}, fmt.Errorf("decode New API log source response: %w", errDecode)
	}
	items := make([]poolSourceLog, 0, len(payload.Items))
	for _, raw := range payload.Items {
		if item, ok := sanitizePoolSourceLog(raw); ok {
			items = append(items, item)
		}
	}
	return poolLogSourcePage{
		Items:        items,
		NextAfterID:  payload.NextAfterID,
		NextBeforeID: payload.NextBeforeID,
		HasMore:      payload.HasMore,
	}, nil
}

func clampPoolLogSourceLimit(limit int) int {
	if limit <= 0 || limit > poolLogSourcePageSize {
		return poolLogSourcePageSize
	}
	return limit
}

func sanitizePoolSourceLog(raw poolSourceLog) (poolSourceLog, bool) {
	if raw.Model != strings.TrimSpace(raw.Model) {
		return poolSourceLog{}, false
	}
	if raw.SourceID <= 0 || raw.CreatedAt <= 0 || !validPoolRequestID(raw.RequestID) {
		return poolSourceLog{}, false
	}
	if raw.UpstreamID != "" && !validPoolRequestID(raw.UpstreamID) {
		return poolSourceLog{}, false
	}
	if raw.Type != 2 && raw.Type != 5 {
		return poolSourceLog{}, false
	}
	if !poolLogModelAllowed(raw.Model) || len(raw.Model) > 128 {
		return poolSourceLog{}, false
	}
	for _, character := range raw.Model {
		if unicode.IsControl(character) || unicode.IsSpace(character) {
			return poolSourceLog{}, false
		}
	}
	if raw.Status < 100 || raw.Status > 599 {
		if raw.Type == 2 {
			raw.Status = http.StatusOK
		} else {
			raw.Status = http.StatusInternalServerError
		}
	}
	if raw.LatencyMS < 0 {
		raw.LatencyMS = 0
	}
	return raw, true
}

func validPoolRequestID(value string) bool {
	if value == "" || len(value) > 128 || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func poolLogModelAllowed(model string) bool {
	return strings.HasPrefix(model, "claude-")
}

type poolLogSourceMetadata struct {
	Kind          string `json:"kind"`
	Name          string `json:"name"`
	Configured    bool   `json:"configured"`
	Available     bool   `json:"available"`
	Stale         bool   `json:"stale"`
	CachedEntries int    `json:"cached_entries"`
	LastSuccessAt int64  `json:"last_success_at,omitempty"`
	LagSeconds    int64  `json:"lag_seconds,omitempty"`
	Status        string `json:"status"`
}

type poolLogService struct {
	pool       *poolSimulator
	source     poolLogSource
	cache      *poolLogCache
	configured bool
	configErr  error
	now        func() time.Time

	mu           sync.RWMutex
	lastSuccess  time.Time
	lastError    error
	failures     int
	nextAttempt  time.Time
	pollStarted  bool
	persistError error
}

var poolLogServiceRegistry sync.Map

func poolLogServiceFor(pool *poolSimulator) *poolLogService {
	if pool == nil {
		return nil
	}
	if existing, ok := poolLogServiceRegistry.Load(pool); ok {
		return existing.(*poolLogService)
	}
	created := newConfiguredPoolLogService(pool)
	actual, loaded := poolLogServiceRegistry.LoadOrStore(pool, created)
	if loaded {
		return actual.(*poolLogService)
	}
	created.start()
	return created
}

func newConfiguredPoolLogService(pool *poolSimulator) *poolLogService {
	rawURL := strings.TrimSpace(os.Getenv(poolLogSourceURLEnvironment))
	cachePath := strings.TrimSpace(os.Getenv(poolLogCachePathEnvironment))
	if cachePath == "" && pool != nil && strings.TrimSpace(pool.path) != "" {
		cachePath = filepath.Join(filepath.Dir(pool.path), "newapi-log-cache.json.gz")
	}
	service := &poolLogService{
		pool:       pool,
		cache:      newPoolLogCache(cachePath, poolLogCacheMaxEntries),
		configured: rawURL != "",
		now:        time.Now,
	}
	if !service.configured {
		service.configErr = errPoolLogSourceNotConfigured
		return service
	}
	tokenFile := strings.TrimSpace(os.Getenv(poolLogSourceTokenFileEnvironment))
	if tokenFile == "" {
		service.configErr = errors.New("New API log source token file is not configured")
		return service
	}
	token, errToken := readPoolLogSourceToken(tokenFile)
	if errToken != nil {
		service.configErr = errToken
		return service
	}
	source, errSource := newBridgePoolLogSource(rawURL, token, nil)
	if errSource != nil {
		service.configErr = errSource
		return service
	}
	service.source = source
	_, _, service.lastSuccess = service.cache.stats()
	return service
}

func readPoolLogSourceToken(path string) (string, error) {
	file, errOpen := os.Open(filepath.Clean(path))
	if errOpen != nil {
		return "", fmt.Errorf("open New API log source token file: %w", errOpen)
	}
	defer func() { _ = file.Close() }()
	data, errRead := io.ReadAll(io.LimitReader(file, 4097))
	if errRead != nil {
		return "", fmt.Errorf("read New API log source token file: %w", errRead)
	}
	if len(data) > 4096 {
		return "", errors.New("New API log source token file is too large")
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", errors.New("New API log source token file is empty")
	}
	for _, character := range token {
		if unicode.IsControl(character) || unicode.IsSpace(character) {
			return "", errors.New("New API log source token file contains whitespace or control characters")
		}
	}
	return token, nil
}

func (s *poolLogService) start() {
	if s == nil || s.source == nil || s.configErr != nil {
		return
	}
	s.mu.Lock()
	if s.pollStarted {
		s.mu.Unlock()
		return
	}
	s.pollStarted = true
	s.mu.Unlock()
	go s.run()
}

func (s *poolLogService) run() {
	poll := time.NewTicker(poolLogPollInterval)
	persist := time.NewTicker(poolLogPersistInterval)
	defer poll.Stop()
	defer persist.Stop()
	s.pollOnce(s.now())
	for {
		select {
		case at := <-poll.C:
			s.pollOnce(at)
		case <-persist.C:
			if errPersist := s.cache.persist(); errPersist != nil {
				s.mu.Lock()
				s.persistError = errPersist
				s.mu.Unlock()
				log.WithError(errPersist).Warn("failed to persist New API pool log cache")
			}
		}
	}
}

func (s *poolLogService) pollOnce(now time.Time) {
	if s == nil || s.source == nil {
		return
	}
	s.mu.RLock()
	nextAttempt := s.nextAttempt
	s.mu.RUnlock()
	if !nextAttempt.IsZero() && now.Before(nextAttempt) {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), poolLogSourceTimeout)
	defer cancel()
	if s.cache.cursor() == 0 {
		if errPrime := s.prime(ctx, now); errPrime != nil {
			s.recordFailure(now, errPrime)
			return
		}
		s.recordSuccess(now)
		return
	}
	if errChanges := s.pullChanges(ctx, now); errChanges != nil {
		s.recordFailure(now, errChanges)
		return
	}
	s.recordSuccess(now)
}

func (s *poolLogService) prime(ctx context.Context, now time.Time) error {
	from := now.Add(-poolLogPrimeWindow)
	beforeID := int64(0)
	maxID := int64(0)
	complete := false
	for pageIndex := 0; pageIndex < poolLogSourceMaxPages; pageIndex++ {
		page, errSearch := s.source.Search(ctx, from, now, beforeID, poolLogSourcePageSize)
		if errSearch != nil {
			return errSearch
		}
		s.cache.add(page.Items, now)
		for _, item := range page.Items {
			if item.SourceID > maxID {
				maxID = item.SourceID
			}
		}
		if page.NextAfterID > maxID {
			maxID = page.NextAfterID
		}
		if !page.HasMore {
			complete = true
			break
		}
		if page.NextBeforeID == 0 || page.NextBeforeID == beforeID {
			break
		}
		beforeID = page.NextBeforeID
	}
	s.cache.markSuccess(now, maxID)
	if complete {
		s.cache.markCoverage(from, now)
	}
	return nil
}

func (s *poolLogService) pullChanges(ctx context.Context, now time.Time) error {
	afterID := s.cache.cursor()
	complete := false
	for pageIndex := 0; pageIndex < poolLogSourceMaxPages; pageIndex++ {
		previousID := afterID
		page, errChanges := s.source.Changes(ctx, afterID, poolLogSourcePageSize)
		if errChanges != nil {
			return errChanges
		}
		s.cache.add(page.Items, now)
		nextID := page.NextAfterID
		for _, item := range page.Items {
			if item.SourceID > nextID {
				nextID = item.SourceID
			}
		}
		if nextID > afterID {
			afterID = nextID
			s.cache.markSuccess(now, afterID)
		}
		if !page.HasMore {
			complete = true
			break
		}
		if nextID <= previousID {
			break
		}
	}
	s.cache.markSuccess(now, afterID)
	if complete {
		s.cache.extendCoverage(now)
	}
	return nil
}

func (s *poolLogService) lookup(ctx context.Context, requestID string) ([]poolSourceLog, error) {
	cached := s.cache.lookup(requestID)
	if s.source == nil {
		if s.configErr != nil {
			return cached, s.configErr
		}
		return cached, errPoolLogSourceUnavailable
	}
	if !s.canAttempt(s.now()) {
		return cached, errPoolLogSourceUnavailable
	}
	requestContext, cancel := context.WithTimeout(ctx, poolLogSourceTimeout)
	defer cancel()
	page, errLookup := s.source.Lookup(requestContext, requestID)
	if errLookup != nil {
		s.recordFailure(s.now(), errLookup)
		return cached, errLookup
	}
	now := s.now()
	s.cache.add(page.Items, now)
	s.cache.markSuccess(now, 0)
	s.recordSuccess(now)
	return page.Items, nil
}

func (s *poolLogService) search(ctx context.Context, from, to time.Time, limit int) ([]poolSourceLog, bool, error) {
	if s.cache.covers(from, to) && !s.metadata(s.now()).Stale {
		items := s.cache.query(from, to, limit)
		return items, len(items) >= limit, nil
	}
	if s.source == nil {
		items := s.cache.query(from, to, limit)
		if s.configErr != nil {
			return items, false, s.configErr
		}
		return items, false, errPoolLogSourceUnavailable
	}
	if !s.canAttempt(s.now()) {
		return s.cache.query(from, to, limit), false, errPoolLogSourceUnavailable
	}

	requestContext, cancel := context.WithTimeout(ctx, poolLogSourceTimeout)
	defer cancel()
	remaining := limit
	if remaining <= 0 || remaining > poolMaxLogLimit {
		remaining = poolMaxLogLimit
	}
	beforeID := int64(0)
	items := make([]poolSourceLog, 0, remaining)
	truncated := false
	complete := false
	for pageIndex := 0; pageIndex < poolLogSourceMaxPages && remaining > 0; pageIndex++ {
		page, errSearch := s.source.Search(requestContext, from, to, beforeID, min(remaining, poolLogSourcePageSize))
		if errSearch != nil {
			s.recordFailure(s.now(), errSearch)
			cached := s.cache.query(from, to, limit)
			return cached, false, errSearch
		}
		items = append(items, page.Items...)
		s.cache.add(page.Items, s.now())
		remaining = limit - len(items)
		truncated = page.HasMore
		if !page.HasMore {
			complete = true
			break
		}
		if page.NextBeforeID == 0 || page.NextBeforeID == beforeID {
			truncated = true
			break
		}
		beforeID = page.NextBeforeID
	}
	now := s.now()
	s.cache.markSuccess(now, 0)
	if complete {
		s.cache.markCoverage(from, to)
	}
	s.recordSuccess(now)
	if len(items) > limit {
		items = items[:limit]
		truncated = true
	}
	return items, truncated, nil
}

func (s *poolLogService) recordSuccess(now time.Time) {
	s.mu.Lock()
	s.lastSuccess = now.UTC()
	s.lastError = nil
	s.failures = 0
	s.nextAttempt = time.Time{}
	s.mu.Unlock()
}

func (s *poolLogService) canAttempt(now time.Time) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.nextAttempt.IsZero() || !now.UTC().Before(s.nextAttempt)
}

func (s *poolLogService) recordFailure(now time.Time, err error) {
	s.mu.Lock()
	s.failures++
	backoff := poolLogPollInterval
	for step := 1; step < s.failures && backoff < time.Minute; step++ {
		backoff *= 2
	}
	if backoff > time.Minute {
		backoff = time.Minute
	}
	s.lastError = err
	s.nextAttempt = now.UTC().Add(backoff)
	s.mu.Unlock()
}

func (s *poolLogService) metadata(now time.Time) poolLogSourceMetadata {
	if s == nil {
		return poolLogSourceMetadata{Kind: "newapi", Name: "new-api", Status: "unavailable", Stale: true}
	}
	entries, _, cachedSuccess := s.cache.stats()
	s.mu.RLock()
	lastSuccess := s.lastSuccess
	lastError := s.lastError
	configErr := s.configErr
	configured := s.configured
	s.mu.RUnlock()
	if lastSuccess.IsZero() {
		lastSuccess = cachedSuccess
	}
	stale := configErr != nil || lastError != nil || lastSuccess.IsZero() || now.UTC().Sub(lastSuccess) > poolLogFreshnessWindow
	status := "ok"
	available := configured && configErr == nil && lastError == nil && !stale
	switch {
	case !configured:
		status = "not_configured"
	case configErr != nil:
		status = "configuration_error"
	case lastError != nil:
		status = "unavailable"
	case stale:
		status = "stale"
	}
	metadata := poolLogSourceMetadata{
		Kind:          "newapi",
		Name:          "new-api",
		Configured:    configured,
		Available:     available,
		Stale:         stale,
		CachedEntries: entries,
		Status:        status,
	}
	if !lastSuccess.IsZero() {
		metadata.LastSuccessAt = lastSuccess.Unix()
		if lag := now.UTC().Unix() - lastSuccess.Unix(); lag > 0 {
			metadata.LagSeconds = lag
		}
	}
	return metadata
}
