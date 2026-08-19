# CPA Claude Credential Pool

This profile runs an isolated CPA management instance containing a persistent,
dynamic pool of synthetic Claude Code account records. It keeps the management
interface, model list, lifecycle events and quota views without storing usable
OAuth tokens or contacting Anthropic.

Request logs come from the narrow read-only bridge documented in
[`pool/log-bridge`](log-bridge/README.md). New API request identifiers, times,
Claude model names, statuses and latencies are preserved. User, token, channel,
IP, prompt, response and raw metadata fields never enter CPA.

```bash
export CPA_POOL_PASSWORD='replace-with-a-random-password'
export CPA_POOL_LOG_SOURCE_TOKEN_PATH='/root-only/path/newapi_log_bridge_token'
docker compose -f pool/docker-compose.yml up --build -d
```

Open `/management.html` and sign in with `CPA_POOL_PASSWORD`. Pool mode adds an
`关联日志` shortcut and serves the dedicated console at `/pool-logs.html`.

## Runtime configuration

Pool mode uses these settings:

| Variable | Meaning |
| --- | --- |
| `CPA_POOL_MODE` | Enables the read-only credential-pool management profile. |
| `CPA_POOL_STATE_PATH` | Persistent lifecycle state, normally `/pool/state/pool-state.json`. |
| `CPA_POOL_LOG_SOURCE_URL` | HTTPS base URL of the restricted New API log bridge. |
| `CPA_POOL_LOG_SOURCE_TOKEN_FILE` | Read-only file containing the bridge Bearer secret. |
| `CPA_POOL_LOG_CACHE_PATH` | Sanitized persistent cache, normally `/pool/state/newapi-log-cache.json.gz`. |

The container root filesystem remains read-only. Account state and the compact
20,000-record log cache share the dedicated state volume; the bridge secret is
mounted separately and never enters that volume.

Management mutations, OAuth initiation and credential downloads return HTTP
403. The only allowed management POST is the intercepted Claude usage/profile
query used by the control panel; it never performs an outbound credential
request. Pool mode also returns 404 for inference, model, websocket and OAuth
callback routes, so the public deployment is management-only and does not need
an inbound API key.

## Log source and failure behaviour

CPA polls the bridge every five seconds by the monotonic New API log row ID and
persists only the safe projection. Initial startup loads at most the most recent
30 minutes/20,000 records rather than replaying the complete New API table.

Bridge failures use exponential backoff up to 60 seconds. Cached list and exact
matches remain available with `source.stale=true`; an uncached exact lookup
returns HTTP 503. CPA never substitutes a locally generated request record when
the bridge is unavailable.

Every New API request is associated with an account that existed at the event
time using a versioned SHA-256 mapping over the persistent pool seed and the
primary request ID. This is a stable presentation association, not evidence
that the synthetic account handled the upstream request. Current accounts stay
in `/auth-files`; retired identities remain available to the dedicated log
account endpoint for 90 days without returning a credential document.

## Log API

`GET /v0/management/logs` keeps the standard management response fields and
accepts:

| Parameter | Meaning |
| --- | --- |
| `from`, `to` | Unix seconds or RFC3339 range bounds, limited to 90 days. |
| `after` | Exclusive incremental timestamp cutoff used by the standard panel. |
| `request_id` | Exact opaque primary or upstream request ID lookup. |
| `q` | Substring match over safe displayed fields. |
| `level` | `INFO`, `WARN`, `ERROR` or `DEBUG`. |
| `limit` | Result cap, default 2,000 and maximum 20,000. |
| `format=json` | Adds structured `entries`, clock information and source health. |

Structured request records include the exact primary/upstream IDs, actual
timestamp, actual `claude-*` model, safe status and latency, plus the associated
masked account fields. Local credential lifecycle records carry
`source="cpa"` and no request ID; bridge records carry `source="newapi"`.

CPA adds a presentation projection without changing either source identifier:

- `cpa_request_id` is the exact New API upstream ID, falling back to the exact
  New API primary ID when no upstream ID was recorded.
- `cpa_upstream_request_id` is a deterministic `req_01`-style identifier
  derived from the exact New API primary ID. It is stable across refreshes and
  deployments, but is not an Anthropic or New API lookup key.
- The existing `request_id` and `upstream_request_id` fields retain the exact
  New API values for provenance and compatibility.

The console displays the CPA projection while exact lookup, cache identity,
account mapping and log downloads continue to use the unmodified New API IDs.
The structured JSON fields remain backward compatible. In the human-readable
`line` value and downloaded text, `request_id`/`upstream_request_id` name the
CPA chain, while `newapi_request_id`/`newapi_upstream_request_id` retain the
exact source values.

The account popup continues to advertise the fixed four-model snapshot used by
the pool. New API logs may display any real model whose name begins `claude-`;
observed traffic never changes the advertised credential model list or quota
state.

## Retention and clocks

- Full quota/profile tombstones remain queryable for 15 minutes after an
  account retires.
- Minimal masked account history and log association are retained for 90 days.
- Rendered log lines use the CPA process timezone. `timestamp` is Unix seconds
  and `time_utc` is RFC3339 UTC.
- Request identifiers are opaque strings. CPA never assumes their length or
  parses a timestamp from them.
