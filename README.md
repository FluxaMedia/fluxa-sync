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

## API status

The initial server provides the health endpoint and migration foundation. Authentication, profile, document, delta-sync, and realtime routes are being added against the stable schema and will remain PostgreSQL-compatible.

## License

MIT.

