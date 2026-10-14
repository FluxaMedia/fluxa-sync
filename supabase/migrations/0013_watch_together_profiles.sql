create or replace function public.create_default_fluxa_profile()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  if coalesce(new.is_anonymous, false) then
    return new;
  end if;
  insert into public.profiles (user_id, name) values (new.id, 'Default');
  return new;
end;
$$;

create or replace function public.reject_anonymous_profile()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  if exists (select 1 from auth.users where id = new.user_id and is_anonymous) then
    raise exception 'anonymous accounts cannot own sync profiles' using errcode = '42501';
  end if;
  return new;
end;
$$;

revoke all on function public.reject_anonymous_profile() from public, anon, authenticated;

drop trigger if exists reject_anonymous_profile on public.profiles;
create trigger reject_anonymous_profile
  before insert on public.profiles
  for each row execute function public.reject_anonymous_profile();

create or replace function public.watch_room_identity(
  p_actor uuid,
  p_name text,
  p_profile_id uuid,
  p_avatar text,
  out o_name text,
  out o_avatar text,
  out o_color text,
  out o_profile uuid
)
language plpgsql
security definer
set search_path = public
as $$
declare
  anonymous boolean := coalesce((auth.jwt() ->> 'is_anonymous')::boolean, false);
  owned public.profiles;
begin
  o_name := coalesce(nullif(left(btrim(coalesce(p_name, '')), 40), ''), 'Guest');
  o_avatar := null;
  o_color := null;
  o_profile := null;

  if not anonymous and p_profile_id is not null then
    select * into owned from public.profiles where id = p_profile_id and user_id = p_actor;
    if found then
      o_name := coalesce(nullif(left(btrim(owned.name), 40), ''), o_name);
      o_avatar := left(owned.avatar, 2048);
      o_color := owned.color;
      o_profile := owned.id;
    end if;
    return;
  end if;

  if p_avatar is not null
     and char_length(p_avatar) <= 2048
     and p_avatar ~ '^https://[^@[:space:]]+$' then
    o_avatar := p_avatar;
  end if;
end;
$$;

revoke all on function public.watch_room_identity(uuid, text, uuid, text) from public, anon, authenticated;
