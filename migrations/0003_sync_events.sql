alter table profiles add column if not exists sync_revision bigint not null default 0;

create table if not exists sync_events (
    id bigserial primary key,
    profile_id uuid not null references profiles(id) on delete cascade,
    entity_type text not null,
    document_key text not null,
    payload jsonb not null,
    deleted boolean not null default false,
    revision bigint not null,
    created_at timestamptz not null default now(),
    unique(profile_id, revision)
);

create index if not exists sync_events_profile_revision_idx on sync_events(profile_id, revision);
