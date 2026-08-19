# CPA New API Log Bridge

This standalone service exposes a narrow, read-only projection of the New API
Claude request logs to the CPA pool. It does not modify New API and does not
claim that a synthetic CPA credential was the credential that served a real
request. CPA performs that stable demonstration-account mapping separately.

## Security boundary

- The Postgres role cannot select the view or any New API base table. It can
  only execute six fixed `cpa_log_bridge` read functions.
- Those functions and the view are owned by the dedicated NOLOGIN,
  NOBYPASSRLS `cpa_log_bridge_owner`, not by the New API application role. The
  owner can select only the eight `public.logs` columns required to construct
  the safe result.
- The SQL view contains exactly `source_id`, `created_at`, `type`,
  `model_name`, `status`, `latency_ms`, `request_id`, and
  `upstream_request_id`, and retains `security_barrier=true` as defense in
  depth.
- Usernames, user IDs, token names, token IDs, IPs, log content, channel data,
  token counts, quota and raw `other` JSON never enter the bridge process.
- Every endpoint, including `/healthz`, requires a constant-time checked
  Bearer token. The image health check reads that token from its mounted file;
  it never places the secret in an environment variable or process argument.
- The container publishes no host port. Caddy is the only ingress and permits
  the bridge path only from `43.156.101.97`.

The Bridge queries only fixed, parameterized `SECURITY DEFINER` functions.
Those functions use `search_path=pg_catalog`, repeat the safe view predicate,
force `row_security=on`, are explicitly `PARALLEL UNSAFE`, return only the
eight approved columns, and enforce hard limits of 1, 100, or 1001 rows.
Search functions independently reject negative/reversed ranges, windows over
90 days, and end times more than 60 seconds in the future. They query
`public.logs` internally so search predicates can use the partial pagination
index without weakening the security-barrier view.

## Database setup

Run the view/function script as a database administrator that may create the
dedicated NOLOGIN owner and grant its narrow column privileges, then create
the dedicated reader with a generated password. The New API application role
must not permanently own the `SECURITY DEFINER` functions. Do not put either
secret in shell history in production; the command below is only an invocation
template.

```bash
psql -d new-api -f pool/log-bridge/sql/001_view.sql
psql -d new-api -v bridge_password='GENERATED_DATABASE_PASSWORD' \
  -f pool/log-bridge/sql/002_reader_role.sql
```

The bridge database URL should use Docker DNS and the reader role:

```text
postgres://cpa_log_reader:GENERATED_DATABASE_PASSWORD@postgres:5432/new-api?sslmode=disable
```

## Standalone deployment bundle

The production directory is self-contained and does not depend on a CPA source
tree above it. Package these files from the repository:

```bash
install -d /opt/cpa-log-bridge/cmd/cpa-log-bridge /opt/cpa-log-bridge/sql
cp go.mod go.sum /opt/cpa-log-bridge/
cp cmd/cpa-log-bridge/*.go /opt/cpa-log-bridge/cmd/cpa-log-bridge/
cp pool/log-bridge/Dockerfile pool/log-bridge/docker-compose.yml \
  pool/log-bridge/Caddyfile.snippet pool/log-bridge/README.md \
  pool/log-bridge/.dockerignore /opt/cpa-log-bridge/
cp pool/log-bridge/sql/*.sql /opt/cpa-log-bridge/sql/
```

Create `/opt/cpa-log-bridge/secrets/database_url` and `bearer_token` through a
secret manager or an interactive root session. Both bind-mounted files must be
owned by `root:65532` and mode `0440`; mode `0600` would make them unreadable to
the non-root container process. Secret values are accepted only through the
`*_FILE` settings. `.dockerignore` excludes the entire secrets directory from
the image build context.

```bash
install -d -o root -g 65532 -m 0750 /opt/cpa-log-bridge/secrets
chown root:65532 /opt/cpa-log-bridge/secrets/database_url \
  /opt/cpa-log-bridge/secrets/bearer_token
chmod 0440 /opt/cpa-log-bridge/secrets/database_url \
  /opt/cpa-log-bridge/secrets/bearer_token
cd /opt/cpa-log-bridge
docker compose up --build -d
```

Apply the SQL files in numeric order. `003_search_index.sql` uses
`CREATE INDEX CONCURRENTLY`, so run it as its own `psql` invocation rather than
wrapping all three files in one transaction. The partial index exists only to
serve stable `(created_at, source_id)` pagination and does not grant the bridge
role any additional table access. Its v2 predicate mirrors every row filter in
the safe view; this is required for PostgreSQL to select the ordered index scan
for 90-day ranges after estimating the length and control-character filters.
Keep the former `idx_cpa_log_bridge_created_id` during validation, then remove
it with `DROP INDEX CONCURRENTLY` only after both range plans use
`idx_cpa_log_bridge_safe_created_id_v2`.

After applying all three SQL files, run `EXPLAIN` as the function owner for the
SQL bodies of first-page and cursor-page searches over both 24-hour and 90-day
ranges; `EXPLAIN SELECT * FROM function(...)` intentionally shows only a
Function Scan to the reader. The underlying search plans must use
`idx_cpa_log_bridge_safe_created_id_v2`; the cursor-boundary lookup must use
`logs_pkey` or `idx_created_at_id`. Reject the rollout if a search plan performs
a sequential scan or sorts the full matching range before applying its limit.

Add `Caddyfile.snippet` to the existing `nlapi.cc` site immediately before its
catch-all New API handle, validate the configuration, and reload Caddy. Both
the exact base path and its wildcard are denied with 404 for non-allowlisted
source addresses. The external URL is:

```text
https://nlapi.cc/internal/cpa-pool/logs
```

## API contract

All timestamps are Unix seconds. Limits are capped server-side.

- `GET /healthz` checks database connectivity and requires the same Bearer
  token as every log endpoint.
- `GET /v1/logs/changes?after_id=0&limit=500` returns rows in ascending
  `source_id` order. Poll again with `next_after_id` until `has_more` is false.
- `GET /v1/logs/search?from=...&to=...&before_id=...&limit=200` returns rows in
  stable `(created_at DESC, source_id DESC)` order. For the next older page,
  pass the last returned `source_id` as `before_id`; the bridge resolves its
  timestamp internally and exposes the cursor as `next_before_id`.
- `GET /v1/logs/lookup?request_id=...` matches either the New API request ID or
  upstream request ID. An exact primary Request ID returns its one row;
  otherwise every matching upstream row is returned newest first, capped at
  100 items. Request IDs are opaque strings and are only rejected when empty,
  over 128 bytes, invalid UTF-8, or containing a control character.

Example:

```bash
curl --config /root/.config/cpa-log-bridge-curl.conf -fsS \
  'https://nlapi.cc/internal/cpa-pool/logs/v1/logs/changes?after_id=0&limit=100'
```

Keep that curl config root-only (`0600`) with its `Authorization` header. This
avoids exposing the bearer token in an environment variable or process
argument.

CPA should consume the service with these settings and keep its cache on the
existing persistent state volume:

```text
CPA_POOL_LOG_SOURCE_URL=https://nlapi.cc/internal/cpa-pool/logs
CPA_POOL_LOG_SOURCE_TOKEN_FILE=/run/secrets/newapi_log_bridge_token
CPA_POOL_LOG_CACHE_PATH=/pool/state/newapi-log-cache.json.gz
```
