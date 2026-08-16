create extension if not exists pgcrypto;

create table if not exists users (
    id uuid primary key default gen_random_uuid(),
    email text not null unique,
    password_hash text not null,
    created_at timestamptz not null default now()
);

create table if not exists profiles (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null references users(id) on delete cascade,
    name text not null,
    avatar text,
    settings jsonb not null default '{}'::jsonb,
    updated_at timestamptz not null default now()
);

create table if not exists sync_documents (
    id uuid primary key default gen_random_uuid(),
    profile_id uuid not null references profiles(id) on delete cascade,
    document_type text not null,
    document_key text not null,
    payload jsonb not null,
    deleted boolean not null default false,
    revision bigint not null default 1,
    updated_at timestamptz not null default now(),
    unique(profile_id, document_type, document_key)
);

create index if not exists sync_documents_profile_revision_idx on sync_documents(profile_id, revision);
