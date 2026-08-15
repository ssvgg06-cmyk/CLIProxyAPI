# CPA Claude Credential Pool

This profile runs an isolated, read-only CPA management instance containing 300
synthetic Claude Code account records. It preserves the management interface,
model listings, rolling request logs, and Claude quota views without storing
usable OAuth tokens or contacting Anthropic.

```bash
export CPA_POOL_PASSWORD='replace-with-a-random-password'
docker compose -f pool/docker-compose.yml up --build -d
```

Open `/management.html` and sign in with the value assigned to
`CPA_POOL_PASSWORD`.

The container joins `new-api-stack_app` so an external Caddy container can
publish it behind HTTPS without exposing the service port publicly. The host
binding remains limited to `127.0.0.1:18317`.

Pool mode is enabled by `CPA_POOL_MODE=true`. Management mutations, OAuth
initiation, and credential downloads return HTTP 403. The only allowed
management POST is the intercepted Claude usage/profile query used by the
control panel. It never performs an outbound request.
