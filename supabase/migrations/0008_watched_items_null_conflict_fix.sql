alter table public.watched_items disable trigger watched_item_delta_trigger;

delete from public.watched_items a
using public.watched_items b
where a.profile_id = b.profile_id
  and a.content_id = b.content_id
  and a.content_type = b.content_type
  and coalesce(a.season, -1) = coalesce(b.season, -1)
  and coalesce(a.episode, -1) = coalesce(b.episode, -1)
  and (a.watched_at, a.created_at, a.id) < (b.watched_at, b.created_at, b.id);

alter table public.watched_items enable trigger watched_item_delta_trigger;

do $$
declare
    v_constraint_name text;
begin
    select con.conname into v_constraint_name
    from pg_constraint con
    join pg_class rel on rel.oid = con.conrelid
    where rel.relname = 'watched_items' and con.contype = 'u';
    if v_constraint_name is not null then
        execute format('alter table public.watched_items drop constraint %I', v_constraint_name);
    end if;
end $$;

create unique index if not exists watched_items_profile_content_season_episode_idx
    on public.watched_items (profile_id, content_id, content_type, coalesce(season, -1), coalesce(episode, -1));

drop function if exists public.sync_apply_change(uuid, text, text, jsonb, boolean, bigint);

create or replace function public.sync_apply_change(
    p_profile_id uuid,
    p_entity_type text,
    p_document_key text,
    p_payload jsonb,
    p_deleted boolean,
    p_revision bigint
) returns bigint
language plpgsql
security definer
set search_path = public
as $$
declare
    item jsonb;
    addon jsonb;
    url text;
    v_content_id text;
    v_content_type text;
    v_progress_key text;
    v_history_content_type text;
    v_revision bigint;
begin
    perform pg_advisory_xact_lock(hashtextextended(p_profile_id::text, 0));
    if not exists (select 1 from public.profiles where id = p_profile_id) then
        raise exception 'profile not found';
    end if;

    select greatest(coalesce(sync_revision, 0) + 1, p_revision)
    into v_revision
    from public.profiles
    where id = p_profile_id
    for update;

    insert into public.sync_documents (profile_id, document_type, document_key, payload, deleted, revision)
    values (p_profile_id, p_entity_type, p_document_key, coalesce(p_payload, 'null'::jsonb), p_deleted, v_revision)
    on conflict (profile_id, document_type, document_key) do update set
        payload = excluded.payload,
        deleted = excluded.deleted,
        revision = excluded.revision,
        updated_at = now();

    insert into public.sync_events (profile_id, entity_type, document_key, payload, deleted, revision)
    values (p_profile_id, p_entity_type, p_document_key, coalesce(p_payload, 'null'::jsonb), p_deleted, v_revision);

    if p_entity_type = 'library' then
        item := p_payload -> 'item';
        v_content_id := item ->> 'id';
        v_content_type := item ->> 'type';
        if p_deleted then
            delete from public.library_items li
            where li.profile_id = p_profile_id and li.content_id = v_content_id and li.content_type = v_content_type;
        else
            insert into public.library_items (
                profile_id, content_id, content_type, status, name, poster, poster_shape,
                background, description, release_info, imdb_rating, genres, addon_base_url,
                added_at, updated_at
            ) values (
                p_profile_id, v_content_id, v_content_type, coalesce(p_payload ->> 'status', 'watchlist'),
                coalesce(item ->> 'name', item ->> 'title', ''), item ->> 'poster',
                coalesce(item ->> 'posterShape', item ->> 'poster_shape', 'POSTER'),
                item ->> 'background', item ->> 'description',
                coalesce(item ->> 'releaseInfo', item ->> 'release_info'),
                coalesce((item ->> 'imdbRating')::real, (item ->> 'imdb_rating')::real),
                array(select jsonb_array_elements_text(coalesce(item -> 'genres', '[]'::jsonb))),
                coalesce(item ->> 'addonBaseUrl', item ->> 'addon_base_url'),
                coalesce((item ->> 'addedAt')::bigint, (item ->> 'added_at')::bigint, 0), now()
            ) on conflict (profile_id, content_id, content_type) do update set
                status = excluded.status, name = excluded.name, poster = excluded.poster,
                poster_shape = excluded.poster_shape, background = excluded.background,
                description = excluded.description, release_info = excluded.release_info,
                imdb_rating = excluded.imdb_rating, genres = excluded.genres,
                addon_base_url = excluded.addon_base_url, added_at = excluded.added_at,
                updated_at = now();
        end if;
    elsif p_entity_type = 'watch_progress' then
        v_progress_key := coalesce(p_payload ->> 'progressKey', p_document_key);
        if p_deleted then
            delete from public.watch_progress where profile_id = p_profile_id and watch_progress.progress_key = v_progress_key;
            insert into public.watch_progress_events (profile_id, operation, progress_key, content_id, content_type)
            values (p_profile_id, 'delete', v_progress_key, coalesce(p_payload ->> 'contentId', ''), coalesce(p_payload ->> 'contentType', ''));
        else
            insert into public.watch_progress (
                profile_id, content_id, content_type, video_id, season, episode, position,
                duration, last_watched, progress_key, last_audio_language,
                last_subtitle_language, last_stream_index, updated_at
            ) values (
                p_profile_id, coalesce(p_payload ->> 'contentId', ''), coalesce(p_payload ->> 'contentType', ''),
                coalesce(p_payload ->> 'videoId', ''), (p_payload ->> 'season')::integer,
                (p_payload ->> 'episode')::integer, coalesce((p_payload ->> 'position')::bigint, 0),
                coalesce((p_payload ->> 'duration')::bigint, 0), coalesce((p_payload ->> 'lastWatched')::bigint, 0),
                v_progress_key, p_payload ->> 'lastAudioLanguage', p_payload ->> 'lastSubtitleLanguage',
                (p_payload ->> 'lastStreamIndex')::integer, now()
            ) on conflict (profile_id, progress_key) do update set
                content_id = excluded.content_id, content_type = excluded.content_type,
                video_id = excluded.video_id, season = excluded.season, episode = excluded.episode,
                position = excluded.position, duration = excluded.duration,
                last_watched = excluded.last_watched, last_audio_language = excluded.last_audio_language,
                last_subtitle_language = excluded.last_subtitle_language,
                last_stream_index = excluded.last_stream_index, updated_at = now();
            insert into public.watch_progress_events (
                profile_id, operation, progress_key, content_id, content_type, video_id,
                season, episode, position, duration, last_watched
            ) values (
                p_profile_id, 'upsert', v_progress_key, coalesce(p_payload ->> 'contentId', ''),
                coalesce(p_payload ->> 'contentType', ''), coalesce(p_payload ->> 'videoId', ''),
                (p_payload ->> 'season')::integer, (p_payload ->> 'episode')::integer,
                coalesce((p_payload ->> 'position')::bigint, 0), coalesce((p_payload ->> 'duration')::bigint, 0),
                coalesce((p_payload ->> 'lastWatched')::bigint, 0)
            );
        end if;
    elsif p_entity_type = 'watched_history' then
        v_content_id := coalesce(p_payload ->> 'videoId', p_document_key);
        v_history_content_type := coalesce(p_payload ->> 'contentType', 'movie');
        if p_deleted or coalesce((p_payload ->> 'watched')::boolean, true) = false then
            delete from public.watched_items
            where profile_id = p_profile_id and watched_items.content_id = v_content_id
              and watched_items.content_type = v_history_content_type
              and watched_items.season is not distinct from (p_payload ->> 'season')::integer
              and watched_items.episode is not distinct from (p_payload ->> 'episode')::integer;
        else
            insert into public.watched_items (profile_id, content_id, content_type, season, episode, watched_at)
            values (p_profile_id, v_content_id, v_history_content_type, (p_payload ->> 'season')::integer,
                    (p_payload ->> 'episode')::integer, coalesce((p_payload ->> 'lastWatched')::bigint, 0))
            on conflict (profile_id, content_id, content_type, coalesce(season, -1), coalesce(episode, -1)) do update set
                watched_at = excluded.watched_at;
        end if;
    elsif p_entity_type = 'addons' then
        delete from public.addons where profile_id = p_profile_id;
        if not p_deleted then
            for addon in select * from jsonb_array_elements(coalesce(p_payload, '[]'::jsonb)) loop
                insert into public.addons (profile_id, url, name, enabled, sort_order)
                values (p_profile_id, addon ->> 'transportUrl', addon #>> '{manifest,name}',
                        coalesce((addon ->> 'enabled')::boolean, true), coalesce((addon ->> 'sortOrder')::integer, 0))
                on conflict (profile_id, url) do update set
                    name = excluded.name, enabled = excluded.enabled, sort_order = excluded.sort_order,
                    updated_at = now();
            end loop;
        end if;
    elsif p_entity_type = 'plugins' then
        delete from public.plugins where profile_id = p_profile_id;
        if not p_deleted then
            for url in select jsonb_array_elements_text(coalesce(p_payload -> 'repositoryUrls', '[]'::jsonb)) loop
                insert into public.plugins (profile_id, url, enabled, sort_order)
                values (p_profile_id, url, true, 0)
                on conflict (profile_id, url) do update set updated_at = now();
            end loop;
        end if;
    elsif p_entity_type = 'collections' then
        if p_deleted then delete from public.collections where profile_id = p_profile_id;
        else insert into public.collections (profile_id, collections_json, updated_at)
             values (p_profile_id, coalesce(p_payload, '[]'::jsonb), now())
             on conflict (profile_id) do update set collections_json = excluded.collections_json, updated_at = now();
        end if;
    elsif p_entity_type = 'settings' then
        if p_deleted then delete from public.profile_settings_blobs where profile_id = p_profile_id and platform = 'fluxa';
        else insert into public.profile_settings_blobs (profile_id, platform, settings_json, updated_at)
             values (p_profile_id, 'fluxa', coalesce(p_payload, '{}'::jsonb), now())
             on conflict (profile_id, platform) do update set settings_json = excluded.settings_json, updated_at = now();
        end if;
    end if;

    update public.profiles
    set sync_revision = greatest(sync_revision, v_revision), updated_at = now()
    where id = p_profile_id;
    return v_revision;
end;
$$;

revoke all on function public.sync_apply_change(uuid, text, text, jsonb, boolean, bigint) from public;
revoke all on function public.sync_apply_change(uuid, text, text, jsonb, boolean, bigint) from anon;
revoke all on function public.sync_apply_change(uuid, text, text, jsonb, boolean, bigint) from authenticated;
grant execute on function public.sync_apply_change(uuid, text, text, jsonb, boolean, bigint) to service_role;
