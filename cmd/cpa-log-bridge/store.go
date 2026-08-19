package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

const changesSQL = `SELECT *
FROM cpa_log_bridge.changes($1, $2)
ORDER BY source_id ASC`

const searchSQL = `SELECT *
FROM cpa_log_bridge.search_initial($1, $2, $3)
ORDER BY created_at DESC, source_id DESC`

// searchBoundarySQL resolves the public single-ID cursor inside a fixed
// SECURITY DEFINER function. The reader has EXECUTE on this narrow function,
// but neither SELECT on the security-barrier view nor on the base table.
const searchBoundarySQL = `SELECT created_at, source_id
FROM cpa_log_bridge.search_boundary($1)
LIMIT 1`

const searchBeforeSQL = `SELECT *
FROM cpa_log_bridge.search_before($1, $2, $3, $4, $5)
ORDER BY created_at DESC, source_id DESC`

const lookupPrimarySQL = `SELECT *
FROM cpa_log_bridge.lookup_primary($1)
ORDER BY source_id DESC
LIMIT 1`

const lookupUpstreamSQL = `SELECT *
FROM cpa_log_bridge.lookup_upstream($1)
ORDER BY source_id DESC
LIMIT 100`

// LogRecord is the complete and intentionally narrow bridge wire format.
// New API usernames, token names, IP addresses, content and the raw other JSON
// are deliberately not represented, so they cannot be serialized by mistake.
type LogRecord struct {
	SourceID          int64  `json:"source_id"`
	CreatedAt         int64  `json:"created_at"`
	Type              int    `json:"type"`
	ModelName         string `json:"model_name"`
	Status            int    `json:"status"`
	LatencyMS         int64  `json:"latency_ms"`
	RequestID         string `json:"request_id"`
	UpstreamRequestID string `json:"upstream_request_id"`
}

type SearchFilter struct {
	From     int64
	To       int64
	BeforeID int64
	Limit    int
}

type LogStore interface {
	Health(context.Context) error
	Changes(context.Context, int64, int) ([]LogRecord, error)
	Search(context.Context, SearchFilter) ([]LogRecord, error)
	Lookup(context.Context, string) ([]LogRecord, error)
	Close() error
}

type postgresStore struct {
	db *sql.DB
}

func newPostgresStore(databaseURL string) (*postgresStore, error) {
	db, errOpen := sql.Open("pgx", databaseURL)
	if errOpen != nil {
		return nil, fmt.Errorf("open postgres: %w", errOpen)
	}
	db.SetMaxOpenConns(8)
	db.SetMaxIdleConns(4)
	db.SetConnMaxIdleTime(5 * time.Minute)
	db.SetConnMaxLifetime(30 * time.Minute)
	return &postgresStore{db: db}, nil
}

func (s *postgresStore) Health(ctx context.Context) error {
	if errPing := s.db.PingContext(ctx); errPing != nil {
		return fmt.Errorf("ping postgres: %w", errPing)
	}
	return nil
}

func (s *postgresStore) Changes(ctx context.Context, afterID int64, limit int) ([]LogRecord, error) {
	rows, errQuery := s.db.QueryContext(ctx, changesSQL, afterID, limit)
	if errQuery != nil {
		return nil, fmt.Errorf("query log changes: %w", errQuery)
	}
	return scanLogRecords(rows)
}

func (s *postgresStore) Search(ctx context.Context, filter SearchFilter) ([]LogRecord, error) {
	var rows *sql.Rows
	var errQuery error
	if filter.BeforeID == 0 {
		rows, errQuery = s.db.QueryContext(
			ctx,
			searchSQL,
			filter.From,
			filter.To,
			filter.Limit,
		)
	} else {
		var boundaryCreatedAt int64
		var boundarySourceID int64
		errBoundary := s.db.QueryRowContext(ctx, searchBoundarySQL, filter.BeforeID).Scan(
			&boundaryCreatedAt,
			&boundarySourceID,
		)
		if errors.Is(errBoundary, sql.ErrNoRows) {
			return []LogRecord{}, nil
		}
		if errBoundary != nil {
			return nil, fmt.Errorf("resolve search cursor: %w", errBoundary)
		}
		rows, errQuery = s.db.QueryContext(
			ctx,
			searchBeforeSQL,
			filter.From,
			filter.To,
			boundaryCreatedAt,
			boundarySourceID,
			filter.Limit,
		)
	}
	if errQuery != nil {
		return nil, fmt.Errorf("search logs: %w", errQuery)
	}
	return scanLogRecords(rows)
}

func (s *postgresStore) Lookup(ctx context.Context, requestID string) ([]LogRecord, error) {
	record, errScan := scanLogRecord(s.db.QueryRowContext(ctx, lookupPrimarySQL, requestID))
	if errScan == nil {
		return []LogRecord{record}, nil
	}
	if !errors.Is(errScan, sql.ErrNoRows) {
		return nil, fmt.Errorf("lookup primary request id: %w", errScan)
	}
	rows, errQuery := s.db.QueryContext(ctx, lookupUpstreamSQL, requestID)
	if errQuery != nil {
		return nil, fmt.Errorf("lookup upstream request id: %w", errQuery)
	}
	return scanLogRecords(rows)
}

func (s *postgresStore) Close() error {
	if errClose := s.db.Close(); errClose != nil {
		return fmt.Errorf("close postgres: %w", errClose)
	}
	return nil
}

type rowScanner interface {
	Scan(...any) error
}

func scanLogRecord(row rowScanner) (LogRecord, error) {
	var record LogRecord
	var upstreamRequestID sql.NullString
	errScan := row.Scan(
		&record.SourceID,
		&record.CreatedAt,
		&record.Type,
		&record.ModelName,
		&record.Status,
		&record.LatencyMS,
		&record.RequestID,
		&upstreamRequestID,
	)
	if errScan != nil {
		return LogRecord{}, errScan
	}
	if upstreamRequestID.Valid {
		record.UpstreamRequestID = upstreamRequestID.String
	}
	normalizeRecord(&record)
	return record, nil
}

func scanLogRecords(rows *sql.Rows) ([]LogRecord, error) {
	defer func() { _ = rows.Close() }()
	records := make([]LogRecord, 0)
	for rows.Next() {
		record, errScan := scanLogRecord(rows)
		if errScan != nil {
			return nil, fmt.Errorf("scan log record: %w", errScan)
		}
		records = append(records, record)
	}
	if errRows := rows.Err(); errRows != nil {
		return nil, fmt.Errorf("iterate log records: %w", errRows)
	}
	return records, nil
}

func normalizeRecord(record *LogRecord) {
	if record == nil {
		return
	}
	if record.LatencyMS < 0 {
		record.LatencyMS = 0
	}
	record.Status = safeStatusCode(record.Type, record.Status)
}

func safeStatusCode(logType int, statusCode int) int {
	if statusCode >= 100 && statusCode <= 599 {
		return statusCode
	}
	if logType == 2 {
		return 200
	}
	return 502
}
