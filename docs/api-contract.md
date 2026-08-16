# Fluxa Sync API contract

Both deployment modes expose the same client-facing routes. The standalone mode implements them in Rust/Axum. The Supabase mode implements them in an Edge Function and uses Supabase Auth and Realtime.

```text
POST /api/v1/auth/register
POST /api/v1/auth/login
POST /api/v1/auth/refresh
POST /api/v1/auth/logout
GET  /api/v1/auth/me
GET  /api/v1/profiles
POST /api/v1/profiles
PATCH /api/v1/profiles/:profile_id
DELETE /api/v1/profiles/:profile_id
GET  /api/v1/sync/snapshot?profile_id=<uuid>
GET  /api/v1/sync/pull?profile_id=<uuid>&since=<revision>
POST /api/v1/sync/push
```

The sync document model is shared: `entity_type`, stable `key`, JSON `payload`, `deleted`, and monotonically increasing profile revisions. Clients must handle `reset_required` by replacing local state from the snapshot cursor.

