# CPA Demo Mode

This profile runs an isolated, read-only CPA management demo. It returns 36
synthetic credential records, rolling synthetic service logs, and downloadable
synthetic error logs. It never stores or exposes usable OAuth credentials.

## Run

```bash
export CPA_DEMO_PASSWORD='replace-with-a-random-password'
docker compose -f demo/docker-compose.yml up --build -d
```

Open `http://127.0.0.1:18317/management.html` and sign in with the value of
`CPA_DEMO_PASSWORD`.

The compose profile also joins the existing `new-api-stack_app` network so an
external Caddy container can publish the demo behind HTTPS without exposing the
backend port publicly.

Demo mode is enabled by `CPA_DEMO_MODE=true`. Management mutations, OAuth
initiation, and credential downloads return HTTP 403. The demo container binds
only to loopback by default and uses a read-only root filesystem.
