-- Serialize concurrent device pushes per profile and allocate the revision on
-- the server. This wraps the atomic 0003 operation without trusting a client
-- supplied revision or changing the already-applied function signature.

create or replace function public.sync_apply_change_locked(
    p_profile_id uuid,
    p_entity_type text,
    p_document_key text,
    p_payload jsonb,
    p_deleted boolean,
    p_requested_revision bigint
) returns bigint
language plpgsql
security definer
set search_path = public
as $$
declare
    v_revision bigint;
begin
    perform pg_advisory_xact_lock(hashtextextended(p_profile_id::text, 0));

    select greatest(coalesce(sync_revision, 0) + 1, p_requested_revision)
    into v_revision
    from public.profiles
    where id = p_profile_id
    for update;

    if v_revision is null then
        raise exception 'profile not found';
    end if;

    perform public.sync_apply_change(
        p_profile_id,
        p_entity_type,
        p_document_key,
        p_payload,
        p_deleted,
        v_revision
    );

    update public.profiles
    set sync_revision = greatest(sync_revision, v_revision), updated_at = now()
    where id = p_profile_id;

    return v_revision;
end;
$$;

revoke all on function public.sync_apply_change_locked(uuid, text, text, jsonb, boolean, bigint) from public;
revoke all on function public.sync_apply_change_locked(uuid, text, text, jsonb, boolean, bigint) from anon;
revoke all on function public.sync_apply_change_locked(uuid, text, text, jsonb, boolean, bigint) from authenticated;
grant execute on function public.sync_apply_change_locked(uuid, text, text, jsonb, boolean, bigint) to service_role;
