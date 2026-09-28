# Fluxa Sync

Fluxa Sync is a self-hosted synchronization API for profiles, settings, libraries, watch progress, history, collections, addon/plugin configuration, and conflict-aware sync.

The server is independent from Fluxa clients and uses PostgreSQL. A Supabase project can be used by providing its PostgreSQL connection string as `DATABASE_URL`; clients always connect to this API, not directly to Supabase.

## Quick start

```sh
cp .env.example .env
docker compose up -d --build
curl http://localhost:8080/health
```

`POSTGRES_PASSWORD` and `JWT_SECRET` have no defaults; Compose refuses to start until both are set in `.env`. The API is published on loopback only, so Internet traffic must pass through a TLS reverse proxy.

For a managed database, set `DATABASE_URL` and `JWT_SECRET` in the deployment environment and run the container without the bundled Postgres service.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `DATABASE_URL` | required | PostgreSQL connection string |
| `JWT_SECRET` | required | access token signing key, at least 32 characters |
| `PORT` / `BIND_ADDRESS` | `8080` / `0.0.0.0` | listen address |
| `ACCESS_TOKEN_TTL_SECONDS` | `3600` | access token lifetime, clamped to 5 minutes–24 hours |
| `AUTH_REQUESTS_PER_MINUTE` | `10` | per-address limit on register, login, and refresh |
| `SYNC_REQUESTS_PER_MINUTE` | `120` | per-user limit on snapshot, pull, and push |
| `TRUST_PROXY_HEADERS` | `false` | honour `X-Forwarded-For` / `X-Real-IP` when behind a trusted proxy |
| `CORS_ALLOWED_ORIGINS` | `*` | comma-separated browser origins |
| `SYNC_EVENT_RETENTION_DAYS` | `30` | age at which `sync_events` rows are compacted |
| `DATABASE_MAX_CONNECTIONS` | `10` | connection pool size |
| `DATABASE_DISABLE_STATEMENT_CACHE` | `0` | set to `1` behind a transaction pooler |

## Deployment

The image works on VPS, Docker-compatible hosts, Fly.io, Railway, Render, and similar platforms. Put the API behind HTTPS, use a unique random `JWT_SECRET`, restrict database network access, and configure automated PostgreSQL backups.

## API

The first API version is intentionally client-agnostic:

```text
POST /api/v1/auth/register
POST /api/v1/auth/login
POST /api/v1/auth/refresh
POST /api/v1/auth/logout
GET  /api/v1/auth/me
POST /api/v1/auth/device/start
POST /api/v1/auth/device/approve
POST /api/v1/auth/device/exchange
GET  /tv-login?code=<user_code>
GET  /.well-known/fluxa
GET  /api/v1/profiles
POST /api/v1/profiles
GET  /api/v1/sync/snapshot?profile_id=<uuid>
GET  /api/v1/sync/pull?profile_id=<uuid>&since=<revision>
POST /api/v1/sync/push
GET  /api/v1/realtime
GET  /health
```

Sync documents use `entity_type` values such as `library`, `watch_progress`, `watched_history`, `collections`, `addons`, `plugins`, and `settings`. A push body contains a profile id and changes with an entity type, stable key, JSON payload, and optional deletion flag. Pull responses are ordered by a monotonic profile revision, making reconnects and delta sync deterministic.

Authentication uses bearer JWT access tokens and rotating one-time refresh tokens. Access tokens are signed by the instance's `JWT_SECRET` and live one hour by default; clients refresh from the `expires_in` field. Refresh tokens expire after 90 days, are stored only as SHA-256 digests, and are revoked on rotation and logout. Presenting an already-rotated refresh token revokes every outstanding token for that account, so a stolen token cannot outlive its detection. Passwords are stored with Argon2id. The service never exposes the database directly to clients.

Register, login, and refresh are rate limited per client address; snapshot, pull, and push are rate limited per user. Push bodies are validated before they reach the database: `entity_type` must be one of the supported entities, keys are capped at 512 bytes, payloads at 512 KB and 1000 changes per request, and any field whose name looks like a credential (`*accessToken`, `*apiKey`, `*secret`, `*password`, `pinHash`, and similar) is rejected outright.

## Supabase deployment mode

The repository also includes a Supabase-native adapter under `supabase/`. It uses Supabase Auth for email/password sessions, Supabase Postgres for the same profile/document/event model, and Supabase Realtime for change notifications.

```sh
supabase link --project-ref YOUR_PROJECT_REF
supabase db push
supabase functions deploy fluxa-sync --no-verify-jwt
```

The client URL for this mode is:

```text
https://YOUR_PROJECT_REF.supabase.co/functions/v1/fluxa-sync
```

The standalone Rust server and Supabase adapter expose the same `/api/v1` contract. Supabase Realtime is notification-only; clients continue from the durable sync cursor after reconnecting.

Push changes may include `expected_revision`. When another device has already changed that document, the server leaves the incoming change unapplied and returns it in `conflicts` with both revisions. The client can then merge the JSON payload and retry.

Event history is compacted automatically according to `SYNC_EVENT_RETENTION_DAYS` (90 by default). A pull response includes `minimum_available_revision` and `reset_required`. If `reset_required` is true, download `/sync/snapshot`, replace the local state, and continue from the snapshot cursor.

The realtime endpoint is a WebSocket event channel. It delivers committed changes only for profiles belonging to the authenticated account; clients still use `/sync/pull` as the durable source of truth after reconnects.

## Running on Supabase's free tier

Both deployment modes fit the free tier if a few things are set correctly:

- **Database size (500MB cap)**: `sync_events`, `watch_progress_events`, and `watched_item_events` are append-only logs. The Rust server compacts `sync_events` on its own hourly timer (`SYNC_EVENT_RETENTION_DAYS`, 30 days by default). The Supabase adapter has no server process to do that, so the `fluxa_sync_retention` `pg_cron` job prunes `sync_events` at 30 days and the delta logs at 7. Confirm `pg_cron` is enabled for the project after running `supabase db push`. `sync_audit_log` is no longer written — it duplicated `sync_events` exactly while carrying a shorter retention — and the cron job drains whatever it still holds.
- **Write amplification**: `sync_apply_change_locked_v2` applies the compatibility document, the event row, and the typed domain row in a single pass. It previously delegated through two more layers, each re-taking the same advisory lock and re-running `update profiles set sync_revision`, so one change cost three profile row updates.
- **Connection limits**: if you point the standalone Rust server's `DATABASE_URL` at a Supabase free-tier project, use the pooled connection string (port `6543`, transaction mode) rather than the direct one (port `5432`) — the free tier's direct-connection quota is small. When using the transaction pooler, set `DATABASE_DISABLE_STATEMENT_CACHE=1`; pgbouncer in transaction mode doesn't guarantee the same backend connection across statements, so sqlx's prepared-statement cache must be off. Keep `DATABASE_MAX_CONNECTIONS` modest (default 10) — a handful of pooled connections comfortably serves thousands of users since each request only holds one for the duration of its query.
- **Edge function invocations**: `sync/push` reads every document a request touches in one query rather than one round trip per change, and batches distinct keys concurrently, which keeps large pushes well under the function's wall-time budget. Access tokens are resolved against Supabase Auth at most once a minute per token instead of once per request. The standalone server collapses a push into two multi-row inserts regardless of how many changes it carries.
- **Egress (5GB/month)**: `sync/pull` returns at most 2000 events per call and sets `has_more` when it truncates, moving the cursor to the last event it returned. `sync/snapshot` no longer downloads generic documents for entities the typed tables already mirror.

Set `PUBLIC_BASE_URL` to the HTTPS public API origin in production so QR codes open the correct approval page. `DEVICE_LOGIN_URL` can override the generated `/tv-login?code=...` URL when a separate web frontend is deployed. On a default `*.supabase.co` domain, edge functions serve HTML as plain text, so host `web/tv-login.html` on any static host (GitHub Pages, Cloudflare Pages), set its `fluxa-api` meta tag to the function URL, and point `DEVICE_LOGIN_URL` at it. `DEVICE_REQUESTS_PER_MINUTE` controls the TV polling budget and defaults to 120.

## Backups

Install PostgreSQL client tools and run:

```sh
DATABASE_URL='postgresql://...' ./scripts/backup.sh ./backup.dump
DATABASE_URL='postgresql://...' ./scripts/restore.sh ./backup.dump
```

Store dumps outside the container, encrypt them at rest, and test restores regularly. Migrations run automatically when the service starts.

## License

MIT.
