package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	log "github.com/sirupsen/logrus"
)

const (
	defaultChangesLimit = 500
	maximumChangesLimit = 1000
	defaultSearchLimit  = 200
	maximumSearchLimit  = 1000
	defaultSearchWindow = 30 * time.Minute
	maximumSearchWindow = 90 * 24 * time.Hour
)

type bridgeServer struct {
	store     LogStore
	tokenHash [sha256.Size]byte
	now       func() time.Time
}

type itemsResponse struct {
	Items []LogRecord `json:"items"`
}

type changesResponse struct {
	Items       []LogRecord `json:"items"`
	NextAfterID int64       `json:"next_after_id"`
	HasMore     bool        `json:"has_more"`
}

type searchResponse struct {
	Items        []LogRecord `json:"items"`
	NextBeforeID int64       `json:"next_before_id"`
	HasMore      bool        `json:"has_more"`
}

type healthResponse struct {
	Status string `json:"status"`
}

type errorBody struct {
	Error apiError `json:"error"`
}

type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func newBridgeServer(store LogStore, bearerToken string) *bridgeServer {
	return &bridgeServer{
		store:     store,
		tokenHash: sha256.Sum256([]byte(bearerToken)),
		now:       time.Now,
	}
}

func (s *bridgeServer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/healthz", s.authorize(http.HandlerFunc(s.health)))
	mux.Handle("/v1/logs/changes", s.authorize(http.HandlerFunc(s.changes)))
	mux.Handle("/v1/logs/search", s.authorize(http.HandlerFunc(s.search)))
	mux.Handle("/v1/logs/lookup", s.authorize(http.HandlerFunc(s.lookup)))
	return s.securityHeaders(mux)
}

func (s *bridgeServer) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

func (s *bridgeServer) authorize(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Fields(r.Header.Get("Authorization"))
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			s.writeUnauthorized(w)
			return
		}
		provided := sha256.Sum256([]byte(parts[1]))
		if subtle.ConstantTimeCompare(provided[:], s.tokenHash[:]) != 1 {
			s.writeUnauthorized(w)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *bridgeServer) writeUnauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="cpa-log-bridge"`)
	writeError(w, http.StatusUnauthorized, "unauthorized", "valid bearer authentication is required")
}

func (s *bridgeServer) health(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		methodNotAllowed(w, http.MethodGet, http.MethodHead)
		return
	}
	if valuesHaveAny(r.URL.Query()) {
		writeError(w, http.StatusBadRequest, "invalid_query", "healthz does not accept query parameters")
		return
	}
	if errHealth := s.store.Health(r.Context()); errHealth != nil {
		log.WithError(errHealth).Warn("log bridge database health check failed")
		writeJSON(w, http.StatusServiceUnavailable, healthResponse{Status: "unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, healthResponse{Status: "ok"})
}

func (s *bridgeServer) changes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	values := r.URL.Query()
	if errKeys := validateQuery(values, "after_id", "limit"); errKeys != nil {
		writeError(w, http.StatusBadRequest, "invalid_query", errKeys.Error())
		return
	}
	afterID, errAfter := queryInt64(values, "after_id", 0, 0)
	if errAfter != nil {
		writeError(w, http.StatusBadRequest, "invalid_after_id", errAfter.Error())
		return
	}
	limit, errLimit := queryLimit(values, defaultChangesLimit, maximumChangesLimit)
	if errLimit != nil {
		writeError(w, http.StatusBadRequest, "invalid_limit", errLimit.Error())
		return
	}
	records, errChanges := s.store.Changes(r.Context(), afterID, limit+1)
	if errChanges != nil {
		log.WithError(errChanges).Warn("log bridge changes query failed")
		writeError(w, http.StatusServiceUnavailable, "source_unavailable", "log source is temporarily unavailable")
		return
	}
	response := pageChanges(records, limit, afterID)
	writeJSON(w, http.StatusOK, response)
}

func (s *bridgeServer) search(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	values := r.URL.Query()
	if errKeys := validateQuery(values, "from", "to", "before_id", "limit"); errKeys != nil {
		writeError(w, http.StatusBadRequest, "invalid_query", errKeys.Error())
		return
	}
	now := s.now().UTC()
	to, errTo := queryInt64(values, "to", now.Unix(), 0)
	if errTo != nil {
		writeError(w, http.StatusBadRequest, "invalid_to", errTo.Error())
		return
	}
	defaultFrom := to - int64(defaultSearchWindow/time.Second)
	if defaultFrom < 0 {
		defaultFrom = 0
	}
	from, errFrom := queryInt64(values, "from", defaultFrom, 0)
	if errFrom != nil {
		writeError(w, http.StatusBadRequest, "invalid_from", errFrom.Error())
		return
	}
	if to < from {
		writeError(w, http.StatusBadRequest, "invalid_range", "to must be greater than or equal to from")
		return
	}
	if to > now.Add(time.Minute).Unix() {
		writeError(w, http.StatusBadRequest, "invalid_to", "to cannot be more than one minute in the future")
		return
	}
	if to-from > int64(maximumSearchWindow/time.Second) {
		writeError(w, http.StatusBadRequest, "invalid_range", "search range cannot exceed 90 days")
		return
	}
	beforeID, errBefore := queryInt64(values, "before_id", 0, 0)
	if errBefore != nil {
		writeError(w, http.StatusBadRequest, "invalid_before_id", errBefore.Error())
		return
	}
	limit, errLimit := queryLimit(values, defaultSearchLimit, maximumSearchLimit)
	if errLimit != nil {
		writeError(w, http.StatusBadRequest, "invalid_limit", errLimit.Error())
		return
	}
	records, errSearch := s.store.Search(r.Context(), SearchFilter{
		From:     from,
		To:       to,
		BeforeID: beforeID,
		Limit:    limit + 1,
	})
	if errSearch != nil {
		log.WithError(errSearch).Warn("log bridge search query failed")
		writeError(w, http.StatusServiceUnavailable, "source_unavailable", "log source is temporarily unavailable")
		return
	}
	writeJSON(w, http.StatusOK, pageSearch(records, limit))
}

func (s *bridgeServer) lookup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	values := r.URL.Query()
	if errKeys := validateQuery(values, "request_id"); errKeys != nil {
		writeError(w, http.StatusBadRequest, "invalid_query", errKeys.Error())
		return
	}
	requestID := values.Get("request_id")
	if !validOpaqueRequestID(requestID) {
		writeError(w, http.StatusBadRequest, "invalid_request_id", "request_id must be non-empty, at most 128 bytes, valid UTF-8, and contain no control characters")
		return
	}
	records, errLookup := s.store.Lookup(r.Context(), requestID)
	if errLookup != nil {
		log.WithError(errLookup).Warn("log bridge request-id lookup failed")
		writeError(w, http.StatusServiceUnavailable, "source_unavailable", "log source is temporarily unavailable")
		return
	}
	if records == nil {
		records = []LogRecord{}
	}
	writeJSON(w, http.StatusOK, itemsResponse{Items: records})
}

func pageChanges(records []LogRecord, limit int, emptyCursor int64) changesResponse {
	hasMore := len(records) > limit
	if hasMore {
		records = records[:limit]
	}
	if records == nil {
		records = []LogRecord{}
	}
	nextAfterID := emptyCursor
	for _, record := range records {
		if record.SourceID > nextAfterID {
			nextAfterID = record.SourceID
		}
	}
	return changesResponse{
		Items:       records,
		NextAfterID: nextAfterID,
		HasMore:     hasMore,
	}
}

func pageSearch(records []LogRecord, limit int) searchResponse {
	hasMore := len(records) > limit
	if hasMore {
		records = records[:limit]
	}
	if records == nil {
		records = []LogRecord{}
	}
	var nextBeforeID int64
	if len(records) > 0 {
		// Search is ordered by (created_at DESC, source_id DESC). The next
		// cursor must therefore identify the last returned tuple; choosing the
		// numerically smallest ID can skip records when IDs and timestamps are
		// not monotonic with one another.
		nextBeforeID = records[len(records)-1].SourceID
	}
	return searchResponse{
		Items:        records,
		NextBeforeID: nextBeforeID,
		HasMore:      hasMore,
	}
}

func validOpaqueRequestID(value string) bool {
	if len(value) == 0 || len(value) > 128 || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validateQuery(values url.Values, allowed ...string) error {
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, key := range allowed {
		allowedSet[key] = struct{}{}
	}
	for key, entries := range values {
		if _, ok := allowedSet[key]; !ok {
			return fmt.Errorf("unsupported query parameter %q", key)
		}
		if len(entries) != 1 {
			return fmt.Errorf("query parameter %q must appear exactly once", key)
		}
	}
	return nil
}

func valuesHaveAny(values url.Values) bool {
	return len(values) != 0
}

func queryInt64(values url.Values, key string, fallback int64, minimum int64) (int64, error) {
	raw := strings.TrimSpace(values.Get(key))
	if raw == "" {
		return fallback, nil
	}
	value, errParse := strconv.ParseInt(raw, 10, 64)
	if errParse != nil || value < minimum {
		return 0, fmt.Errorf("%s must be an integer greater than or equal to %d", key, minimum)
	}
	return value, nil
}

func queryLimit(values url.Values, fallback int, maximum int) (int, error) {
	raw := strings.TrimSpace(values.Get("limit"))
	if raw == "" {
		return fallback, nil
	}
	value, errParse := strconv.Atoi(raw)
	if errParse != nil || value < 1 || value > maximum {
		return 0, fmt.Errorf("limit must be between 1 and %d", maximum)
	}
	return value, nil
}

func methodNotAllowed(w http.ResponseWriter, methods ...string) {
	w.Header().Set("Allow", strings.Join(methods, ", "))
	writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
}

func writeError(w http.ResponseWriter, status int, code string, message string) {
	writeJSON(w, status, errorBody{Error: apiError{Code: code, Message: message}})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if errEncode := json.NewEncoder(w).Encode(value); errEncode != nil {
		log.WithError(errEncode).Warn("log bridge response encoding failed")
	}
}
