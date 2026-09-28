create or replace function public.claim_device_login(p_session_id uuid, p_poll_secret_hash text)
returns table (status text, user_id uuid)
language plpgsql
security definer
set search_path = public
as $$
declare
    s public.device_login_sessions;
begin
    select * into s from public.device_login_sessions d where d.id = p_session_id and d.poll_secret_hash = p_poll_secret_hash for update;
    if not found then
        return;
    end if;
    if s.consumed_at is not null then
        return query select 'consumed'::text, null::uuid;
    elsif s.expires_at <= now() then
        return query select 'expired'::text, null::uuid;
    elsif s.approved_user_id is null then
        return query select 'pending'::text, null::uuid;
    else
        update public.device_login_sessions d set consumed_at = now() where d.id = p_session_id;
        return query select 'claimed'::text, s.approved_user_id;
    end if;
end $$;

revoke all on function public.claim_device_login(uuid, text) from public, anon, authenticated;
grant execute on function public.claim_device_login(uuid, text) to service_role;
