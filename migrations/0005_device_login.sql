create table if not exists device_login_sessions (
    id uuid primary key default gen_random_uuid(),
    code_hash text not null unique,
    poll_secret_hash text not null unique,
    device_name text,
    approved_user_id uuid references users(id) on delete cascade,
    approved_at timestamptz,
    consumed_at timestamptz,
    expires_at timestamptz not null,
    created_at timestamptz not null default now()
);

create index if not exists device_login_sessions_expiry_idx on device_login_sessions(expires_at);
