create table if not exists public.device_login_sessions (
    id uuid primary key default gen_random_uuid(),
    code_hash text not null unique,
    poll_secret_hash text not null unique,
    device_name text,
    client_ip text,
    approved_user_id uuid references auth.users(id) on delete cascade,
    approved_at timestamptz,
    consumed_at timestamptz,
    expires_at timestamptz not null,
    created_at timestamptz not null default now()
);

create index if not exists device_login_sessions_expiry_idx on public.device_login_sessions(expires_at);
create index if not exists device_login_sessions_ip_idx on public.device_login_sessions(client_ip, created_at);

do $$
begin
    perform cron.unschedule(jobid) from cron.job where jobname = 'fluxa_device_login_cleanup';
exception when others then
    null;
end $$;

select cron.schedule(
    'fluxa_device_login_cleanup',
    '17 * * * *',
    $cron$
    delete from public.device_login_sessions where expires_at < now() - interval '1 hour';
    $cron$
);
