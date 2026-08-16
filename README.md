# Fluxa Sync

Fluxa Sync is a self-hosted synchronization API for profiles, settings, libraries, watch progress, history, collections, addon/plugin configuration, and conflict-aware sync.

The server is independent from Fluxa clients and uses PostgreSQL. A Supabase project can be used by providing its PostgreSQL connection string as `DATABASE_URL`; clients always connect to this API, not directly to Supabase.

## Quick start

```sh
cp .env.example .env
docker compose up -d --build
curl http://localhost:8080/health
```

For a managed database, set `DATABASE_URL` and `JWT_SECRET` in the deployment environment and run the container without the bundled Postgres service.

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
GET  /api/v1/profiles
POST /api/v1/profiles
GET  /api/v1/sync/snapshot?profile_id=<uuid>
GET  /api/v1/sync/pull?profile_id=<uuid>&since=<revision>
POST /api/v1/sync/push
GET  /api/v1/realtime
GET  /health
```

Sync documents use `entity_type` values such as `library`, `watch_progress`, `watched_history`, `collections`, `addons`, `plugins`, and `settings`. A push body contains a profile id and changes with an entity type, stable key, JSON payload, and optional deletion flag. Pull responses are ordered by a monotonic profile revision, making reconnects and delta sync deterministic.

Authentication uses bearer JWT access tokens and rotating one-time refresh tokens. Access tokens are signed by the instance's `JWT_SECRET`, refresh tokens expire after 90 days and are revoked on rotation/logout, and passwords are stored with Argon2id. The service never exposes the database directly to clients.

Push changes may include `expected_revision`. When another device has already changed that document, the server leaves the incoming change unapplied and returns it in `conflicts` with both revisions. The client can then merge the JSON payload and retry.

The realtime endpoint is a WebSocket event channel. It broadcasts committed profile changes; clients still use `/sync/pull` as the durable source of truth after reconnects.

## Backups

Install PostgreSQL client tools and run:

```sh
DATABASE_URL='postgresql://...' ./scripts/backup.sh ./backup.dump
DATABASE_URL='postgresql://...' ./scripts/restore.sh ./backup.dump
```

Store dumps outside the container, encrypt them at rest, and test restores regularly. Migrations run automatically when the service starts.

## License

MIT.
