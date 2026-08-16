import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.57.4'

const supabaseUrl = Deno.env.get('SUPABASE_URL')!
const anonKey = Deno.env.get('SUPABASE_ANON_KEY')!
const serviceKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!
const authClient = createClient(supabaseUrl, anonKey)
const db = createClient(supabaseUrl, serviceKey)

const cors = { 'access-control-allow-origin': '*', 'access-control-allow-headers': 'authorization, content-type', 'access-control-allow-methods': 'GET, POST, PATCH, DELETE, OPTIONS' }

function response(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { ...cors, 'content-type': 'application/json' } })
}

async function user(request: Request) {
  const token = request.headers.get('authorization')?.replace(/^Bearer\s+/i, '')
  if (!token) return null
  const result = await authClient.auth.getUser(token)
  return result.data.user ?? null
}

async function profileOwner(request: Request, profileId: string) {
  const current = await user(request)
  if (!current) return null
  const result = await db.from('profiles').select('id').eq('id', profileId).eq('user_id', current.id).maybeSingle()
  return result.data ? current : null
}

async function auth(request: Request, action: string) {
  if (action === 'me') {
    const current = await user(request)
    return current ? { data: { id: current.id, email: current.email }, error: null } : { data: null, error: { message: 'unauthorized' } }
  }
  const body = await request.json()
  if (action === 'register') return authClient.auth.signUp({ email: body.email, password: body.password })
  if (action === 'login') return authClient.auth.signInWithPassword({ email: body.email, password: body.password })
  if (action === 'refresh') return authClient.auth.refreshSession({ refresh_token: body.refresh_token })
  if (action === 'logout') {
    const result = await authClient.auth.signOut()
    return { data: {}, error: result.error }
  }
  return null
}

async function syncSnapshot(request: Request, profileId: string) {
  if (!await profileOwner(request, profileId)) return response({ error: 'unauthorized' }, 401)
  const [documents, profile] = await Promise.all([
    db.from('sync_documents').select('document_type,document_key,payload,deleted,revision,updated_at').eq('profile_id', profileId).order('revision'),
    db.from('profiles').select('sync_revision').eq('id', profileId).single(),
  ])
  if (documents.error || profile.error) return response({ error: 'database error' }, 500)
  return response({ profile_id: profileId, cursor: profile.data.sync_revision, documents: documents.data })
}

async function syncPull(request: Request, profileId: string, since: number) {
  if (!await profileOwner(request, profileId)) return response({ error: 'unauthorized' }, 401)
  const [events, profile, minimum] = await Promise.all([
    db.from('sync_events').select('entity_type,document_key,payload,deleted,revision,created_at').eq('profile_id', profileId).gt('revision', since).order('revision'),
    db.from('profiles').select('sync_revision').eq('id', profileId).single(),
    db.from('sync_events').select('revision').eq('profile_id', profileId).order('revision').limit(1).maybeSingle(),
  ])
  if (events.error || profile.error || minimum.error) return response({ error: 'database error' }, 500)
  const minRevision = minimum.data?.revision ?? null
  const cursor = profile.data.sync_revision
  const reset = since > 0 && (minRevision === null ? since < cursor : since < minRevision - 1)
  return response({ profile_id: profileId, since, cursor, minimum_available_revision: minRevision, reset_required: reset, changes: events.data })
}

async function syncPush(request: Request) {
  const body = await request.json()
  if (!await profileOwner(request, body.profile_id)) return response({ error: 'unauthorized' }, 401)
  const profileId = body.profile_id as string
  const profile = await db.from('profiles').select('sync_revision').eq('id', profileId).single()
  if (profile.error) return response({ error: 'database error' }, 500)
  let revision = profile.data.sync_revision as number
  const applied = []
  const conflicts = []
  for (const change of body.changes ?? []) {
    const existing = await db.from('sync_documents').select('revision').eq('profile_id', profileId).eq('document_type', change.entity_type).eq('document_key', change.key).maybeSingle()
    if (change.expected_revision !== undefined && (existing.data?.revision ?? 0) !== change.expected_revision) {
      conflicts.push({ entity_type: change.entity_type, key: change.key, expected_revision: change.expected_revision, actual_revision: existing.data?.revision ?? 0 })
      continue
    }
    revision += 1
    const payload = change.payload ?? null
    const deleted = change.deleted === true
    const document = await db.from('sync_documents').upsert({ profile_id: profileId, document_type: change.entity_type, document_key: change.key, payload, deleted, revision }, { onConflict: 'profile_id,document_type,document_key' })
    const event = await db.from('sync_events').insert({ profile_id: profileId, entity_type: change.entity_type, document_key: change.key, payload, deleted, revision })
    if (document.error || event.error) return response({ error: 'database error' }, 500)
    applied.push({ entity_type: change.entity_type, key: change.key, revision, deleted })
  }
  const update = await db.from('profiles').update({ sync_revision: revision, updated_at: new Date().toISOString() }).eq('id', profileId)
  if (update.error) return response({ error: 'database error' }, 500)
  return response({ profile_id: profileId, cursor: revision, applied, conflicts })
}

async function profiles(request: Request, profileId?: string) {
  const current = await user(request)
  if (!current) return response({ error: 'unauthorized' }, 401)
  if (request.method === 'GET') {
    const result = await db.from('profiles').select('id,name,avatar,settings,updated_at').eq('user_id', current.id).order('updated_at')
    return result.error ? response({ error: 'database error' }, 500) : response(result.data)
  }
  if (request.method === 'POST') {
    const body = await request.json()
    const result = await db.from('profiles').insert({ user_id: current.id, name: body.name, avatar: body.avatar ?? null, settings: body.settings ?? {} }).select('id,name,avatar,settings,updated_at').single()
    return result.error ? response({ error: result.error.message }, 400) : response(result.data, 201)
  }
  if (!profileId || !(await profileOwner(request, profileId))) return response({ error: 'unauthorized' }, 401)
  if (request.method === 'PATCH') {
    const body = await request.json()
    const result = await db.from('profiles').update({ name: body.name, avatar: body.avatar, settings: body.settings, updated_at: new Date().toISOString() }).eq('id', profileId).select('id,name,avatar,settings,updated_at').single()
    return result.error ? response({ error: 'database error' }, 500) : response(result.data)
  }
  if (request.method === 'DELETE') {
    const result = await db.from('profiles').delete().eq('id', profileId)
    return result.error ? response({ error: 'database error' }, 500) : new Response(null, { status: 204, headers: cors })
  }
  return response({ error: 'method not allowed' }, 405)
}

Deno.serve(async (request) => {
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors })
  const url = new URL(request.url)
  const parts = url.pathname.split('/').filter(Boolean)
  try {
    if (parts.at(-2) === 'auth') {
      const result = await auth(request, parts.at(-1)!)
      if (!result || result.error) return response({ error: result?.error?.message ?? 'unsupported auth action' }, 400)
      return response(result.data)
    }
    if (parts.at(-2) === 'sync' && parts.at(-1) === 'snapshot') return syncSnapshot(request, new URL(request.url).searchParams.get('profile_id')!)
    if (parts.at(-2) === 'sync' && parts.at(-1) === 'pull') return syncPull(request, new URL(request.url).searchParams.get('profile_id')!, Number(new URL(request.url).searchParams.get('since') ?? 0))
    if (parts.at(-2) === 'sync' && parts.at(-1) === 'push') return syncPush(request)
    if (parts.at(-2) === 'profiles') return profiles(request, parts.at(-1) === 'profiles' ? undefined : parts.at(-1))
    if (parts.at(-1) === 'profiles') return profiles(request)
    return response({ error: 'not found' }, 404)
  } catch (error) {
    return response({ error: error instanceof Error ? error.message : 'request failed' }, 500)
  }
})
