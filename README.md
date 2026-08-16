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
GET  /api/v1/auth/me
GET  /api/v1/profiles
POST /api/v1/profiles
GET  /api/v1/sync/snapshot?profile_id=<uuid>
GET  /api/v1/sync/pull?profile_id=<uuid>&since=<revision>
POST /api/v1/sync/push
GET  /health
```

Sync documents use `entity_type` values such as `library`, `watch_progress`, `watched_history`, `collections`, `addons`, `plugins`, and `settings`. A push body contains a profile id and changes with an entity type, stable key, JSON payload, and optional deletion flag. Pull responses are ordered by a monotonic profile revision, making reconnects and delta sync deterministic.

Authentication uses short-lived bearer JWTs signed by the instance's `JWT_SECRET`; passwords are stored with Argon2id. The service never exposes the database directly to clients.

## License

MIT.
