alter table public.profiles add column if not exists color text;
alter table public.profiles add column if not exists uses_primary_addons boolean;
alter table public.profiles add column if not exists uses_primary_plugins boolean;

create or replace function public.sync_apply_change_locked_v2(
    p_profile_id uuid,
    p_entity_type text,
    p_document_key text,
    p_payload jsonb,
    p_deleted boolean,
    p_requested_revision bigint
) returns bigint
language plpgsql security definer set search_path = public
as $$
declare
    v_revision bigint;
begin
    v_revision := public.sync_apply_change_locked(
        p_profile_id, p_entity_type, p_document_key, p_payload, p_deleted, p_requested_revision
    );

    if p_entity_type = 'settings' and p_document_key = 'profile' then
        if p_deleted then
            update public.profiles
            set color = null, uses_primary_addons = null, uses_primary_plugins = null, updated_at = now()
            where id = p_profile_id;
        else
            update public.profiles
            set name = coalesce(p_payload ->> 'name', name),
                avatar = coalesce(p_payload ->> 'avatarUrl', avatar),
                color = p_payload ->> 'color',
                uses_primary_addons = (p_payload ->> 'usesPrimaryAddons')::boolean,
                uses_primary_plugins = (p_payload ->> 'usesPrimaryPlugins')::boolean,
                updated_at = now()
            where id = p_profile_id;
        end if;
        delete from public.profile_settings_blobs
        where profile_id = p_profile_id and platform = 'fluxa';
    end if;
    return v_revision;
end;
$$;

revoke all on function public.sync_apply_change_locked_v2(uuid, text, text, jsonb, boolean, bigint) from public;
revoke all on function public.sync_apply_change_locked_v2(uuid, text, text, jsonb, boolean, bigint) from anon;
revoke all on function public.sync_apply_change_locked_v2(uuid, text, text, jsonb, boolean, bigint) from authenticated;
grant execute on function public.sync_apply_change_locked_v2(uuid, text, text, jsonb, boolean, bigint) to service_role;
