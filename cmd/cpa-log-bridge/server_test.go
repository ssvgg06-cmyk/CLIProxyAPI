package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const testBearerToken = "0123456789abcdef0123456789abcdef01234567"

type fakeLogStore struct {
	healthErr error
	changes   []LogRecord
	changeErr error
	search    []LogRecord
	searchErr error
	lookup    []LogRecord
	lookupErr error

	afterID      int64
	changesLimit int
	searchFilter SearchFilter
	lookupID     string
}

func (f *fakeLogStore) Health(context.Context) error { return f.healthErr }

func (f *fakeLogStore) Changes(_ context.Context, afterID int64, limit int) ([]LogRecord, error) {
	f.afterID = afterID
	f.changesLimit = limit
	return f.changes, f.changeErr
}

func (f *fakeLogStore) Search(_ context.Context, filter SearchFilter) ([]LogRecord, error) {
	f.searchFilter = filter
	return f.search, f.searchErr
}

func (f *fakeLogStore) Lookup(_ context.Context, requestID string) ([]LogRecord, error) {
	f.lookupID = requestID
	return f.lookup, f.lookupErr
}

func (f *fakeLogStore) Close() error { return nil }

func newAuthorizedRequest(method string, target string) *http.Request {
	request := httptest.NewRequest(method, target, nil)
	request.Header.Set("Authorization", "Bearer "+testBearerToken)
	return request
}

func TestHealthRequiresBearerAndReportsDatabaseState(t *testing.T) {
	store := &fakeLogStore{}
	handler := newBridgeServer(store, testBearerToken).handler()
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated health response = %d, want 401", recorder.Code)
	}
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, newAuthorizedRequest(http.MethodGet, "/healthz"))
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"status":"ok"`) {
		t.Fatalf("healthy response = %d %s", recorder.Code, recorder.Body.String())
	}

	store.healthErr = errors.New("database unavailable")
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, newAuthorizedRequest(http.MethodGet, "/healthz"))
	if recorder.Code != http.StatusServiceUnavailable || !strings.Contains(recorder.Body.String(), `"status":"unavailable"`) {
		t.Fatalf("unhealthy response = %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestProtectedEndpointsRequireExactBearerToken(t *testing.T) {
	store := &fakeLogStore{}
	handler := newBridgeServer(store, testBearerToken).handler()
	for _, header := range []string{"", "Basic abc", "Bearer wrong", "Bearer " + testBearerToken + " extra"} {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/v1/logs/changes", nil)
		request.Header.Set("Authorization", header)
		handler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("Authorization %q returned %d, want 401", header, recorder.Code)
		}
	}
}

func TestChangesPaginatesAndReturnsOnlyWhitelistedFields(t *testing.T) {
	store := &fakeLogStore{changes: []LogRecord{
		{SourceID: 11, CreatedAt: 100, Type: 2, ModelName: "claude-opus-5", Status: 200, LatencyMS: 900, RequestID: "rid11", UpstreamRequestID: "upid11"},
		{SourceID: 12, CreatedAt: 101, Type: 5, ModelName: "claude-opus-5", Status: 429, LatencyMS: 1000, RequestID: "rid12"},
		{SourceID: 13, CreatedAt: 102, Type: 2, ModelName: "claude-sonnet-5", Status: 200, LatencyMS: 1100, RequestID: "rid13"},
	}}
	handler := newBridgeServer(store, testBearerToken).handler()
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, newAuthorizedRequest(http.MethodGet, "/v1/logs/changes?after_id=10&limit=2"))
	if recorder.Code != http.StatusOK {
		t.Fatalf("response = %d %s", recorder.Code, recorder.Body.String())
	}
	if store.afterID != 10 || store.changesLimit != 3 {
		t.Fatalf("store received after_id=%d limit=%d", store.afterID, store.changesLimit)
	}
	var payload map[string]any
	if errDecode := json.Unmarshal(recorder.Body.Bytes(), &payload); errDecode != nil {
		t.Fatal(errDecode)
	}
	if payload["next_after_id"] != float64(12) || payload["has_more"] != true {
		t.Fatalf("unexpected pagination: %#v", payload)
	}
	items, ok := payload["items"].([]any)
	if !ok || len(items) != 2 {
		t.Fatalf("items = %#v", payload["items"])
	}
	first := items[0].(map[string]any)
	allowed := map[string]bool{
		"source_id": true, "created_at": true, "type": true, "model_name": true,
		"status": true, "latency_ms": true, "request_id": true, "upstream_request_id": true,
	}
	for key := range first {
		if !allowed[key] {
			t.Fatalf("unexpected serialized field %q", key)
		}
	}
}

func TestSearchValidatesRangeAndUsesBeforeCursor(t *testing.T) {
	store := &fakeLogStore{search: []LogRecord{
		{SourceID: 7, CreatedAt: 9900},
		{SourceID: 29, CreatedAt: 9800},
		{SourceID: 28, CreatedAt: 9700},
	}}
	server := newBridgeServer(store, testBearerToken)
	server.now = func() time.Time { return time.Unix(10_000, 0) }
	handler := server.handler()
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, newAuthorizedRequest(http.MethodGet, "/v1/logs/search?from=9000&to=9900&before_id=31&limit=2"))
	if recorder.Code != http.StatusOK {
		t.Fatalf("response = %d %s", recorder.Code, recorder.Body.String())
	}
	if store.searchFilter != (SearchFilter{From: 9000, To: 9900, BeforeID: 31, Limit: 3}) {
		t.Fatalf("filter = %#v", store.searchFilter)
	}
	var payload searchResponse
	if errDecode := json.Unmarshal(recorder.Body.Bytes(), &payload); errDecode != nil {
		t.Fatal(errDecode)
	}
	if !payload.HasMore || payload.NextBeforeID != 29 || len(payload.Items) != 2 {
		t.Fatalf("payload = %#v", payload)
	}
	if payload.Items[0].SourceID != 7 || payload.Items[1].SourceID != 29 {
		t.Fatalf("page order changed: %#v", payload.Items)
	}

	for _, target := range []string{
		"/v1/logs/search?from=1&to=2&model=claude-opus-5",
		"/v1/logs/search?from=10&to=9",
		"/v1/logs/search?from=1&to=9000000",
	} {
		recorder = httptest.NewRecorder()
		handler.ServeHTTP(recorder, newAuthorizedRequest(http.MethodGet, target))
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("%s returned %d, want 400", target, recorder.Code)
		}
	}
}

func TestPageSearchUsesLastCompositeOrderedItemAsCursor(t *testing.T) {
	// IDs deliberately run against timestamp order. A minimum-ID cursor would
	// return 7 and skip the second record when the next page resolves its tuple.
	records := []LogRecord{
		{SourceID: 7, CreatedAt: 300},
		{SourceID: 99, CreatedAt: 200},
		{SourceID: 50, CreatedAt: 200},
	}
	payload := pageSearch(records, 2)
	if !payload.HasMore || payload.NextBeforeID != 99 {
		t.Fatalf("payload = %#v, want cursor for last returned item 99", payload)
	}
	if len(payload.Items) != 2 || payload.Items[0].SourceID != 7 || payload.Items[1].SourceID != 99 {
		t.Fatalf("items = %#v", payload.Items)
	}
}

func TestLookupMatchesOpaqueRequestOrUpstreamIDAndUsesEmptyItemsForMissing(t *testing.T) {
	store := &fakeLogStore{lookup: []LogRecord{
		{SourceID: 45, RequestID: "request45", UpstreamRequestID: "opaque upstream/id"},
		{SourceID: 44, RequestID: "request44", UpstreamRequestID: "opaque upstream/id"},
	}}
	handler := newBridgeServer(store, testBearerToken).handler()
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, newAuthorizedRequest(http.MethodGet, "/v1/logs/lookup?request_id=opaque+upstream%2Fid"))
	if recorder.Code != http.StatusOK || store.lookupID != "opaque upstream/id" {
		t.Fatalf("lookup response = %d %s, id=%q", recorder.Code, recorder.Body.String(), store.lookupID)
	}
	var matched itemsResponse
	if errDecode := json.Unmarshal(recorder.Body.Bytes(), &matched); errDecode != nil || len(matched.Items) != 2 {
		t.Fatalf("lookup items = %#v, error = %v", matched.Items, errDecode)
	}

	store.lookup = nil
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, newAuthorizedRequest(http.MethodGet, "/v1/logs/lookup?request_id=missing"))
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"items":[]`) {
		t.Fatalf("missing response = %d %s", recorder.Code, recorder.Body.String())
	}

	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, newAuthorizedRequest(http.MethodGet, "/v1/logs/lookup?request_id=bad%0Aid"))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("unsafe request id returned %d", recorder.Code)
	}
}

func TestStrictQueryAndMethodValidation(t *testing.T) {
	handler := newBridgeServer(&fakeLogStore{}, testBearerToken).handler()
	tests := []struct {
		method string
		target string
		want   int
	}{
		{method: http.MethodGet, target: "/v1/logs/changes?after_id=1&after_id=2", want: http.StatusBadRequest},
		{method: http.MethodGet, target: "/v1/logs/changes?limit=1001", want: http.StatusBadRequest},
		{method: http.MethodGet, target: "/v1/logs/lookup", want: http.StatusBadRequest},
		{method: http.MethodPost, target: "/v1/logs/changes", want: http.StatusMethodNotAllowed},
	}
	for _, test := range tests {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, newAuthorizedRequest(test.method, test.target))
		if recorder.Code != test.want {
			t.Fatalf("%s %s returned %d, want %d", test.method, test.target, recorder.Code, test.want)
		}
	}
}

func TestOpaqueRequestIDValidation(t *testing.T) {
	tests := []struct {
		value string
		want  bool
	}{
		{value: "opaque / request?id=1", want: true},
		{value: "", want: false},
		{value: strings.Repeat("x", 128), want: true},
		{value: strings.Repeat("x", 129), want: false},
		{value: "line\nbreak", want: false},
		{value: string([]byte{0xff}), want: false},
	}
	for _, test := range tests {
		if got := validOpaqueRequestID(test.value); got != test.want {
			t.Fatalf("validOpaqueRequestID(%q) = %t, want %t", test.value, got, test.want)
		}
	}
}
