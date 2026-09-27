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

const sensitiveField = /^(?:.*(?:access|refresh)[_-]?token|.*(?:api[_-]?key|secret|password|passwd|authorization)|pinHash|nuvioAccessToken|nuvioRefreshToken|stremioToken)$/i
const entityTypes = new Set(['library', 'watch_progress', 'watched_history', 'collections', 'addons', 'plugins', 'settings'])
const maxPullChanges = 2000
const deviceLoginTtlSeconds = 300
const deviceStartsPerMinute = 10

async function sha256Hex(value: string) {
  const bytes = new TextEncoder().encode(value)
  const digest = await crypto.subtle.digest('SHA-256', bytes)
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, '0')).join('')
}

function deviceCode() {
  const bytes = crypto.getRandomValues(new Uint8Array(5))
  return [...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('').slice(0, 8).toUpperCase()
}

function deviceLoginUrl(code: string) {
  const base = Deno.env.get('DEVICE_LOGIN_URL') ?? `${Deno.env.get('PUBLIC_BASE_URL') ?? 'http://localhost:54321/functions/v1/fluxa-sync'}/tv-login`
  return `${base}${base.includes('?') ? '&' : '?'}code=${encodeURIComponent(code)}`
}

function deviceLoginPage(request: Request) {
  const url = new URL(request.url)
  const code = url.searchParams.get('code')?.trim().toUpperCase() ?? ''
  const apiRoot = url.pathname.replace(/\/tv-login\/?$/, '')
  const safeCode = JSON.stringify(code).replace(/</g, '\\u003c')
  const html = `<!doctype html><meta name="viewport" content="width=device-width,initial-scale=1"><title>Connect Fluxa TV</title><style>body{font:16px system-ui;background:#101010;color:#fff;max-width:420px;margin:10vh auto;padding:24px}input,button{box-sizing:border-box;width:100%;padding:14px;margin:6px 0;border-radius:8px;border:1px solid #555;background:#191919;color:#fff}button{background:#fff;color:#111;font-weight:700}#message{margin-top:16px}</style><h1>Connect Fluxa TV</h1><p>Enter your Fluxa account to connect this TV.</p><form id="form"><input id="email" type="email" autocomplete="email" placeholder="Email" required><input id="password" type="password" autocomplete="current-password" placeholder="Password" required><button>Connect TV</button></form><div id="message"></div><script>const code=${safeCode},root=${JSON.stringify(apiRoot)};const message=document.querySelector('#message');document.querySelector('#form').addEventListener('submit',async event=>{event.preventDefault();message.textContent='Connecting…';try{const login=await fetch(root+'/api/v1/auth/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({email:email.value,password:password.value})});const auth=await login.json();const token=auth.data?.access_token;if(!login.ok||!token)throw Error(auth.error||'Login failed');const approve=await fetch(root+'/api/v1/auth/device/approve',{method:'POST',headers:{'content-type':'application/json',authorization:'Bearer '+token},body:JSON.stringify({code})});if(!approve.ok)throw Error('Code expired or invalid');form.remove();message.textContent='TV connected. You can close this page.'}catch(error){message.textContent=error.message||'Could not connect TV'}}</script>`
  return new Response(html, { status: 200, headers: { ...cors, 'content-type': 'text/html; charset=utf-8' } })
}

function sensitivePath(value: unknown, path = 'payload'): string | null {
  if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index += 1) {
      const found = sensitivePath(value[index], `${path}[${index}]`)
      if (found) return found
    }
    return null
  }
  if (!value || typeof value !== 'object') return null
  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    if (sensitiveField.test(key)) return `${path}.${key}`
    const found = sensitivePath(child, `${path}.${key}`)
    if (found) return found
  }
  return null
}

function validHttpUrl(value: unknown): boolean {
  if (typeof value !== 'string' || value.length > 2048) return false
  try {
    const url = new URL(value)
    if ((url.protocol !== 'http:' && url.protocol !== 'https:') || url.username || url.password) return false
    return [...url.searchParams.keys()].every((key) => !sensitiveField.test(key))
  } catch {
    return false
  }
}

function canonicalJson(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalJson)
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b)).map(([key, child]) => [key, canonicalJson(child)]))
  }
  return value
}

function samePayload(left: unknown, right: unknown): boolean {
  return JSON.stringify(canonicalJson(left)) === JSON.stringify(canonicalJson(right))
}

function validateEntityPayload(entity: string, payload: unknown): string | null {
  if (payload === null || typeof payload !== 'object') return `${entity} payload must be an object or array`
  if (entity === 'addons') {
    if (!Array.isArray(payload) || payload.length > 500) return 'addons payload must be an array of at most 500 items'
    for (const addon of payload) {
      if (!addon || typeof addon !== 'object') return 'each addon must be an object'
      const item = addon as Record<string, unknown>
      const manifest = item.manifest as Record<string, unknown> | undefined
      const url = item.transportUrl ?? item.url
      if (manifest) {
        if (typeof manifest.id !== 'string' || typeof manifest.name !== 'string') return 'addon manifest id and name are required'
      } else if (typeof item.name !== 'string') {
        return 'normalized addon name is required'
      }
      if (!validHttpUrl(url)) return 'addon URL must be an http(s) URL without credentials'
    }
  }
  if (entity === 'plugins') {
    const value = payload as Record<string, unknown>
    if (!Array.isArray(value.repositoryUrls) || value.repositoryUrls.length > 200 || !value.repositoryUrls.every(validHttpUrl)) {
      return 'plugins.repositoryUrls must contain only http(s) URLs without credentials'
    }
    if (!value.scraperOverrides || typeof value.scraperOverrides !== 'object' || Array.isArray(value.scraperOverrides)) {
      return 'plugins.scraperOverrides must be an object'
    }
    if (!Object.values(value.scraperOverrides as Record<string, unknown>).every((entry) => typeof entry === 'boolean')) {
      return 'plugins.scraperOverrides values must be boolean'
    }
  }
  if (entity === 'library') {
    const value = payload as Record<string, unknown>
    const item = value.item as Record<string, unknown> | undefined
    if (!['watchlist', 'completed', 'dropped'].includes(String(value.status))) return 'library status is invalid'
    if (!item || typeof item.id !== 'string' || typeof item.type !== 'string') return 'library item id and type are required'
  }
  if (entity === 'watched_history') {
    const value = payload as Record<string, unknown>
    if (Object.keys(value).some((key) => !['watched', 'contentType', 'videoId', 'season', 'episode', 'lastWatched'].includes(key))) return 'watched history metadata is not allowed'
    if (value.contentType !== undefined && typeof value.contentType !== 'string') return 'watched history contentType must be a string'
  }
  if (entity === 'watch_progress') {
    const allowed = ['contentId', 'contentType', 'videoId', 'season', 'episode', 'position', 'duration', 'lastWatched', 'progressKey', 'lastAudioLanguage', 'lastSubtitleLanguage', 'lastStreamIndex']
    if (Object.keys(payload as Record<string, unknown>).some((key) => !allowed.includes(key))) return 'watch progress metadata is not allowed'
    const value = payload as Record<string, unknown>
    if (typeof value.contentId !== 'string' || typeof value.contentType !== 'string' || typeof value.position !== 'number' || typeof value.duration !== 'number') return 'watch progress identity and timing are required'
  }
  if (entity === 'settings' && (payload as Record<string, unknown>).profile) {
    return 'profile settings must use key profile, not a nested profile payload'
  }
  if (entity === 'settings' && typeof payload === 'object') {
    const value = payload as Record<string, unknown>
    if (value.name !== undefined && typeof value.name !== 'string') return 'profile name must be a string'
    if (value.avatarUrl !== undefined && value.avatarUrl !== null && !validHttpUrl(value.avatarUrl)) return 'profile avatarUrl must be an http(s) URL'
    for (const key of ['usesPrimaryAddons', 'usesPrimaryPlugins']) {
      if (value[key] !== undefined && typeof value[key] !== 'boolean') return `${key} must be boolean`
    }
  }
  return null
}

function validateProfileBody(body: Record<string, unknown>, requireName: boolean): string | null {
  if (requireName || body.name !== undefined) {
    if (typeof body.name !== 'string' || body.name.trim().length < 1 || body.name.length > 160) return 'profile name is required'
  }
  if (body.avatar !== undefined && body.avatar !== null && !validHttpUrl(body.avatar)) return 'profile avatar must be an http(s) URL without credentials'
  const unsafe = sensitivePath(body.settings ?? {}, 'settings')
  return unsafe ? `sensitive field is not allowed: ${unsafe}` : null
}

function validateChange(change: unknown): string | null {
  if (!change || typeof change !== 'object') return 'each change must be an object'
  const value = change as Record<string, unknown>
  const entity = value.entity_type
  const key = value.key
  if (typeof entity !== 'string' || !entityTypes.has(entity)) return 'unsupported entity_type'
  if (typeof key !== 'string' || key.length < 1 || key.length > 512) return 'invalid document key'
  if (value.expected_revision !== undefined && (!Number.isInteger(value.expected_revision) || (value.expected_revision as number) < 0)) {
    return 'expected_revision must be a non-negative integer'
  }
  const unsafe = sensitivePath(value.payload)
  if (unsafe) return `sensitive field is not allowed: ${unsafe}`
  if (value.deleted === true) return value.payload == null ? null : 'deleted changes must not include a payload'
  if (JSON.stringify(value.payload ?? null).length > 512_000) return 'payload is too large'
  return validateEntityPayload(entity, value.payload)
}

function shouldThrottleProgress(previous: unknown, incoming: unknown): boolean {
  if (!previous || typeof previous !== 'object' || !incoming || typeof incoming !== 'object') return false
  const oldValue = previous as Record<string, unknown>
  const nextValue = incoming as Record<string, unknown>
  for (const key of ['contentId', 'contentType', 'videoId', 'season', 'episode', 'duration', 'progressKey']) {
    if (oldValue[key] !== nextValue[key]) return false
  }
  const oldPosition = typeof oldValue.position === 'number' ? oldValue.position : 0
  const nextPosition = typeof nextValue.position === 'number' ? nextValue.position : 0
  const oldWatched = typeof oldValue.lastWatched === 'number' ? oldValue.lastWatched : 0
  const nextWatched = typeof nextValue.lastWatched === 'number' ? nextValue.lastWatched : 0
  const crossedCompletion = nextValue.duration && nextPosition >= Number(nextValue.duration) * 0.9
    && !(oldValue.duration && oldPosition >= Number(oldValue.duration) * 0.9)
  return Math.abs(nextPosition - oldPosition) < 15_000 && nextWatched - oldWatched < 30_000 && !crossedCompletion
}

function numberValue(value: unknown, fallback = 0): number {
  return typeof value === 'number' && Number.isFinite(value) ? Math.trunc(value) : fallback
}

function textValue(value: unknown, fallback = ''): string {
  return typeof value === 'string' ? value : fallback
}

function libraryRow(profileId: string, status: string, item: Record<string, unknown>) {
  return {
    profile_id: profileId,
    content_id: textValue(item.id),
    content_type: textValue(item.type),
    status,
    name: textValue(item.name ?? item.title),
    poster: typeof item.poster === 'string' ? item.poster : null,
    poster_shape: textValue(item.posterShape ?? item.poster_shape, 'POSTER'),
    background: typeof item.background === 'string' ? item.background : null,
    description: typeof item.description === 'string' ? item.description : null,
    release_info: typeof (item.releaseInfo ?? item.release_info) === 'string' ? (item.releaseInfo ?? item.release_info) : null,
    imdb_rating: typeof (item.imdbRating ?? item.imdb_rating) === 'number' ? (item.imdbRating ?? item.imdb_rating) : null,
    genres: Array.isArray(item.genres) ? item.genres.filter((entry): entry is string => typeof entry === 'string') : [],
    addon_base_url: typeof (item.addonBaseUrl ?? item.addon_base_url) === 'string' ? (item.addonBaseUrl ?? item.addon_base_url) : null,
    added_at: numberValue(item.addedAt ?? item.added_at),
    updated_at: new Date().toISOString(),
  }
}

async function mirrorDomain(profileId: string, change: Record<string, any>) {
  const entity = change.entity_type as string
  const deleted = change.deleted === true
  const payload = change.payload as any

  if (entity === 'library') {
    const item = payload?.item as Record<string, unknown> | undefined
    if (!item) return
    const contentId = textValue(item.id)
    const contentType = textValue(item.type)
    if (deleted) {
      await db.from('library_items').delete().eq('profile_id', profileId).eq('content_id', contentId).eq('content_type', contentType)
    } else {
      const result = await db.from('library_items').upsert(libraryRow(profileId, textValue(payload.status, 'watchlist'), item), { onConflict: 'profile_id,content_id,content_type' })
      if (result.error) throw result.error
    }
    return
  }

  if (entity === 'watch_progress') {
    const value = payload as Record<string, unknown>
    const row = {
      profile_id: profileId,
      content_id: textValue(value.contentId),
      content_type: textValue(value.contentType),
      video_id: textValue(value.videoId),
      season: typeof value.season === 'number' ? value.season : null,
      episode: typeof value.episode === 'number' ? value.episode : null,
      position: numberValue(value.position),
      duration: numberValue(value.duration),
      last_watched: numberValue(value.lastWatched),
      progress_key: textValue(value.progressKey, change.key),
      last_audio_language: typeof value.lastAudioLanguage === 'string' ? value.lastAudioLanguage : null,
      last_subtitle_language: typeof value.lastSubtitleLanguage === 'string' ? value.lastSubtitleLanguage : null,
      last_stream_index: typeof value.lastStreamIndex === 'number' ? value.lastStreamIndex : null,
      updated_at: new Date().toISOString(),
    }
    if (deleted) {
      await db.from('watch_progress').delete().eq('profile_id', profileId).eq('progress_key', row.progress_key)
    } else {
      const result = await db.from('watch_progress').upsert(row, { onConflict: 'profile_id,progress_key' })
      if (result.error) throw result.error
      const event = await db.from('watch_progress_events').insert({ ...row, operation: 'upsert' })
      if (event.error) throw event.error
    }
    return
  }

  if (entity === 'watched_history') {
    const value = payload as Record<string, unknown>
    const row = {
      profile_id: profileId,
      content_id: textValue(value.videoId, change.key),
      content_type: 'unknown',
      title: '',
      season: typeof value.season === 'number' ? value.season : null,
      episode: typeof value.episode === 'number' ? value.episode : null,
      watched_at: numberValue(value.lastWatched),
    }
    if (deleted || value.watched === false) {
      await db.from('watched_items').delete().eq('profile_id', profileId).eq('content_id', row.content_id).eq('season', row.season).eq('episode', row.episode)
    } else {
      const result = await db.from('watched_items').upsert(row, { onConflict: 'profile_id,content_id,content_type,season,episode' })
      if (result.error) throw result.error
    }
    return
  }

  if (entity === 'addons' && Array.isArray(payload)) {
    await db.from('addons').delete().eq('profile_id', profileId)
    const rows = payload.map((addon: any, index: number) => ({
      profile_id: profileId,
      url: addon.transportUrl ?? addon.url,
      name: addon.manifest?.name ?? addon.name ?? null,
      enabled: addon.enabled !== false,
      sort_order: index,
    }))
    if (rows.length) {
      const result = await db.from('addons').insert(rows)
      if (result.error) throw result.error
    }
    return
  }

  if (entity === 'plugins' && payload && typeof payload === 'object') {
    await db.from('plugins').delete().eq('profile_id', profileId)
    const urls = Array.isArray(payload.repositoryUrls) ? payload.repositoryUrls : []
    if (urls.length) {
      const rows = urls.map((url: string, index: number) => ({ profile_id: profileId, url, enabled: true, sort_order: index }))
      const result = await db.from('plugins').insert(rows)
      if (result.error) throw result.error
    }
    return
  }

  if (entity === 'collections') {
    const result = await db.from('collections').upsert({ profile_id: profileId, collections_json: payload ?? [], updated_at: new Date().toISOString() }, { onConflict: 'profile_id' })
    if (result.error) throw result.error
    return
  }

  if (entity === 'settings') {
    const result = await db.from('profile_settings_blobs').upsert({ profile_id: profileId, platform: 'fluxa', settings_json: payload ?? {}, updated_at: new Date().toISOString() }, { onConflict: 'profile_id,platform' })
    if (result.error) throw result.error
  }
}

const userCache = new Map<string, { account: Record<string, any>; expiresAt: number }>()

function bearer(request: Request) {
  return request.headers.get('authorization')?.replace(/^Bearer\s+/i, '') ?? null
}

async function user(request: Request) {
  const token = bearer(request)
  if (!token) return null
  const cached = userCache.get(token)
  if (cached && cached.expiresAt > Date.now()) return cached.account
  const result = await authClient.auth.getUser(token)
  const account = result.data.user ?? null
  if (account) {
    if (userCache.size > 500) userCache.clear()
    userCache.set(token, { account, expiresAt: Date.now() + 60_000 })
  }
  return account
}

async function profileContext(request: Request, profileId: string) {
  const current = await user(request)
  if (!current || typeof profileId !== 'string') return null
  const result = await db.from('profiles').select('id,sync_revision').eq('id', profileId).eq('user_id', current.id).maybeSingle()
  return result.data ? { account: current, cursor: result.data.sync_revision as number } : null
}

function sessionBody(data: Record<string, any>) {
  const session = data?.session ?? null
  const account = data?.user ?? session?.user ?? null
  return {
    access_token: session?.access_token ?? null,
    refresh_token: session?.refresh_token ?? null,
    token_type: 'bearer',
    expires_in: session?.expires_in ?? null,
    user: account ? { id: account.id, email: account.email, created_at: account.created_at } : null,
  }
}

async function auth(request: Request, action: string) {
  if (action === 'me') {
    const current = await user(request)
    return current
      ? { data: { id: current.id, email: current.email, created_at: current.created_at }, error: null }
      : { data: null, error: { message: 'unauthorized' } }
  }
  const body = await request.json()
  if (action === 'register') {
    const result = await authClient.auth.signUp({ email: body.email, password: body.password })
    return result.error ? result : { data: sessionBody(result.data), error: null }
  }
  if (action === 'login') {
    const result = await authClient.auth.signInWithPassword({ email: body.email, password: body.password })
    return result.error ? result : { data: sessionBody(result.data), error: null }
  }
  if (action === 'refresh') {
    const result = await authClient.auth.refreshSession({ refresh_token: body.refresh_token })
    return result.error ? result : { data: sessionBody(result.data), error: null }
  }
  if (action === 'logout') {
    const token = bearer(request)
    if (!token) return { data: null, error: { message: 'unauthorized' } }
    userCache.delete(token)
    const result = await db.auth.admin.signOut(token, 'global')
    return { data: {}, error: result.error }
  }
  return null
}

async function deviceAuth(request: Request, action: string) {
  if (action === 'start' && request.method === 'POST') {
    const clientIp = request.headers.get('x-forwarded-for')?.split(',')[0].trim() || null
    if (clientIp) {
      const recent = await db.from('device_login_sessions').select('id', { count: 'exact', head: true })
        .eq('client_ip', clientIp).gt('created_at', new Date(Date.now() - 60_000).toISOString())
      if (recent.error) return response({ error: 'database error' }, 500)
      if ((recent.count ?? 0) >= deviceStartsPerMinute) return response({ error: 'too many requests' }, 429)
    }
    const body = await request.json().catch(() => ({}))
    const code = deviceCode()
    const pollSecret = crypto.randomUUID().replaceAll('-', '')
    const sessionId = crypto.randomUUID()
    const result = await db.from('device_login_sessions').insert({
      id: sessionId,
      code_hash: await sha256Hex(code),
      poll_secret_hash: await sha256Hex(pollSecret),
      client_ip: clientIp,
      device_name: typeof body.device_name === 'string' ? body.device_name.trim().slice(0, 120) || null : null,
      expires_at: new Date(Date.now() + deviceLoginTtlSeconds * 1000).toISOString(),
    })
    if (result.error) return response({ error: 'database error' }, 500)
    return response({ session_id: sessionId, user_code: code, verification_uri: deviceLoginUrl(code), poll_secret: pollSecret, expires_in: deviceLoginTtlSeconds, poll_interval: 5 })
  }

  if (action === 'approve' && request.method === 'POST') {
    const current = await user(request)
    if (!current) return response({ error: 'unauthorized' }, 401)
    const body = await request.json().catch(() => ({}))
    const code = typeof body.code === 'string' ? body.code.trim().toUpperCase() : ''
    if (!/^[A-Z0-9]{8}$/.test(code)) return response({ error: 'invalid device code' }, 400)
    const result = await db.from('device_login_sessions').update({ approved_user_id: current.id, approved_at: new Date().toISOString() })
      .eq('code_hash', await sha256Hex(code)).is('approved_user_id', null).is('consumed_at', null).gt('expires_at', new Date().toISOString())
      .select('id', { count: 'exact', head: true })
    return result.error ? response({ error: 'database error' }, 500) : new Response(null, { status: result.count === 0 ? 400 : 204, headers: cors })
  }

  const body = await request.json().catch(() => ({}))
  const sessionId = typeof body.session_id === 'string' ? body.session_id : ''
  const pollSecret = typeof body.poll_secret === 'string' ? body.poll_secret : ''
  const session = await db.from('device_login_sessions').select('approved_user_id,expires_at,consumed_at').eq('id', sessionId).eq('poll_secret_hash', await sha256Hex(pollSecret)).maybeSingle()
  if (session.error || !session.data) return response({ error: 'unauthorized' }, 401)
  if (session.data.consumed_at) return response({ error: 'device session already consumed' }, 400)
  if (new Date(session.data.expires_at).getTime() <= Date.now()) return response({ status: 'expired' })
  if (action !== 'exchange' || !session.data.approved_user_id) return response({ status: 'pending' })

  const account = await db.auth.admin.getUserById(session.data.approved_user_id)
  const email = account.data.user?.email
  if (account.error || !email) return response({ error: 'account unavailable' }, 500)
  const link = await db.auth.admin.generateLink({ type: 'magiclink', email })
  const properties = link.data?.properties as Record<string, unknown> | undefined
  const tokenHash = properties?.hashed_token
  if (link.error || typeof tokenHash !== 'string') return response({ error: 'could not create device session' }, 500)
  const verified = await authClient.auth.verifyOtp({ type: 'magiclink', token_hash: tokenHash })
  if (verified.error || !verified.data.session) return response({ error: 'could not create device session' }, 500)
  const consumed = await db.from('device_login_sessions').update({ consumed_at: new Date().toISOString() }).eq('id', sessionId).is('consumed_at', null)
  if (consumed.error) return response({ error: 'database error' }, 500)
  return response({ status: 'authorized', ...sessionBody(verified.data) })
}

async function syncSnapshot(request: Request, profileId: string) {
  const context = await profileContext(request, profileId)
  if (!context) return response({ error: 'unauthorized' }, 401)
  const [library, progress, history] = await Promise.all([
    db.from('library_items').select('*').eq('profile_id', profileId),
    db.from('watch_progress').select('*').eq('profile_id', profileId),
    db.from('watched_items').select('*').eq('profile_id', profileId),
  ])
  if (library.error || progress.error || history.error) return response({ error: 'database error' }, 500)

  const cursor = context.cursor
  const mirrored: string[] = []
  if (library.data?.length) mirrored.push('library')
  if (progress.data?.length) mirrored.push('watch_progress')
  if (history.data?.length) mirrored.push('watched_history')
  let genericQuery = db.from('sync_documents').select('document_type,document_key,payload,deleted,revision,updated_at').eq('profile_id', profileId).order('revision')
  if (mirrored.length) genericQuery = genericQuery.not('document_type', 'in', `(${mirrored.join(',')})`)
  const documents = await genericQuery
  if (documents.error) return response({ error: 'database error' }, 500)
  const generic: Record<string, any>[] = documents.data ?? []
  const typedEntities = new Set<string>()
  const typedDocuments: any[] = []
  const appendTyped = (entity_type: string, document_key: string, payload: unknown) => {
    typedEntities.add(entity_type)
    typedDocuments.push({ entity_type, document_key, payload, deleted: false, revision: cursor, updated_at: new Date().toISOString() })
  }

  for (const row of library.data ?? []) {
    appendTyped('library', row.content_id, {
      status: row.status,
      item: {
        id: row.content_id,
        type: row.content_type,
        name: row.name,
        poster: row.poster,
        posterShape: row.poster_shape,
        background: row.background,
        description: row.description,
        releaseInfo: row.release_info,
        imdbRating: row.imdb_rating,
        genres: row.genres,
        addonBaseUrl: row.addon_base_url,
        addedAt: row.added_at,
      },
    })
  }
  for (const row of progress.data ?? []) {
    appendTyped('watch_progress', row.progress_key, {
      contentId: row.content_id,
      contentType: row.content_type,
      videoId: row.video_id,
      season: row.season,
      episode: row.episode,
      position: row.position,
      duration: row.duration,
      lastWatched: row.last_watched,
      progressKey: row.progress_key,
      lastAudioLanguage: row.last_audio_language,
      lastSubtitleLanguage: row.last_subtitle_language,
      lastStreamIndex: row.last_stream_index,
    })
  }
  for (const row of history.data ?? []) {
    const key = row.season === null || row.episode === null ? `video:${row.content_id}` : `series:${row.content_id}`
    appendTyped('watched_history', key, {
      watched: true,
      videoId: row.content_id,
      season: row.season,
      episode: row.episode,
      lastWatched: row.watched_at,
    })
  }

  const documentsForSnapshot = [
    ...generic.filter((document) => !typedEntities.has(document.document_type)),
    ...typedDocuments,
  ]
  return response({ profile_id: profileId, cursor, documents: documentsForSnapshot })
}

async function syncPull(request: Request, profileId: string, since: number) {
  const context = await profileContext(request, profileId)
  if (!context) return response({ error: 'unauthorized' }, 401)
  const [events, minimum] = await Promise.all([
    db.from('sync_events').select('entity_type,document_key,payload,deleted,revision,created_at').eq('profile_id', profileId).gt('revision', since).order('revision').limit(maxPullChanges),
    db.from('sync_events').select('revision').eq('profile_id', profileId).order('revision').limit(1).maybeSingle(),
  ])
  if (events.error || minimum.error) return response({ error: 'database error' }, 500)
  const minRevision = minimum.data?.revision ?? null
  const changes = events.data ?? []
  const truncated = changes.length === maxPullChanges
  const cursor = truncated ? changes[changes.length - 1].revision : context.cursor
  const reset = since > 0 && (minRevision === null ? since < context.cursor : since < minRevision - 1)
  return response({ profile_id: profileId, since, cursor, minimum_available_revision: minRevision, reset_required: reset, has_more: truncated, changes })
}

async function syncPush(request: Request) {
  const body = await request.json()
  if (typeof body.profile_id !== 'string' || !Array.isArray(body.changes) || body.changes.length > 1000) {
    return response({ error: 'profile_id and at most 1000 changes are required' }, 400)
  }
  const context = await profileContext(request, body.profile_id)
  if (!context) return response({ error: 'unauthorized' }, 401)
  for (const change of body.changes) {
    const validationError = validateChange(change)
    if (validationError) return response({ error: validationError }, 400)
  }
  const profileId = body.profile_id as string
  const limit = await db.rpc('sync_check_rate_limit', { p_profile_id: profileId, p_max_requests: 120 })
  if (limit.error) return response({ error: 'database error' }, 500)
  if (limit.data === false) return response({ error: 'rate limit exceeded' }, 429)
  let revision = context.cursor
  const changes = body.changes ?? []
  const results: ({ kind: 'applied' | 'conflict'; value: Record<string, unknown> } | null)[] = new Array(changes.length).fill(null)
  let databaseError = false

  const groups = new Map<string, number[]>()
  changes.forEach((change: Record<string, unknown>, index: number) => {
    const groupKey = `${change.entity_type} ${change.key}`
    const indexes = groups.get(groupKey) ?? []
    indexes.push(index)
    groups.set(groupKey, indexes)
  })

  const current = new Map<string, { revision: number; payload: unknown; deleted: boolean }>()
  if (changes.length) {
    const prefetch = await db.from('sync_documents').select('document_type,document_key,revision,payload,deleted')
      .eq('profile_id', profileId)
      .in('document_type', [...new Set(changes.map((change: Record<string, unknown>) => change.entity_type as string))])
      .in('document_key', [...new Set(changes.map((change: Record<string, unknown>) => change.key as string))])
    if (prefetch.error) return response({ error: 'database error' }, 500)
    for (const row of prefetch.data ?? []) {
      current.set(`${row.document_type} ${row.document_key}`, { revision: row.revision, payload: row.payload, deleted: row.deleted })
    }
  }

  await Promise.all([...groups.entries()].map(async ([groupKey, indexes]) => {
    for (const index of indexes) {
      if (databaseError) return
      const change = changes[index]
      const existing = current.get(groupKey) ?? null
      if (change.expected_revision !== undefined && (existing?.revision ?? 0) !== change.expected_revision) {
        results[index] = { kind: 'conflict', value: { entity_type: change.entity_type, key: change.key, expected_revision: change.expected_revision, actual_revision: existing?.revision ?? 0 } }
        continue
      }
      if (existing && existing.deleted === (change.deleted === true) && samePayload(existing.payload, change.payload ?? null)) {
        results[index] = { kind: 'applied', value: { entity_type: change.entity_type, key: change.key, revision: existing.revision, deleted: change.deleted === true } }
        continue
      }
      if (change.entity_type === 'watch_progress' && existing?.deleted !== true && shouldThrottleProgress(existing?.payload, change.payload)) {
        results[index] = { kind: 'applied', value: { entity_type: change.entity_type, key: change.key, revision: existing?.revision ?? revision, deleted: false } }
        continue
      }
      revision += 1
      const requestedRevision = revision
      const payload = change.payload ?? null
      const deleted = change.deleted === true
      const appliedChange = await db.rpc('sync_apply_change_locked_v2', {
        p_profile_id: profileId,
        p_entity_type: change.entity_type,
        p_document_key: change.key,
        p_payload: payload,
        p_deleted: deleted,
        p_requested_revision: requestedRevision,
      })
      if (appliedChange.error) { databaseError = true; return }
      const parsedRevision = Number(appliedChange.data)
      const appliedRevision = Number.isSafeInteger(parsedRevision) ? parsedRevision : requestedRevision
      revision = Math.max(revision, appliedRevision)
      current.set(groupKey, { revision: appliedRevision, payload, deleted })
      results[index] = { kind: 'applied', value: { entity_type: change.entity_type, key: change.key, revision: appliedRevision, deleted } }
    }
  }))

  if (databaseError) return response({ error: 'database error' }, 500)

  const applied = []
  const conflicts = []
  for (const result of results) {
    if (!result) continue
    if (result.kind === 'applied') applied.push(result.value)
    else conflicts.push(result.value)
  }
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
    const validationError = validateProfileBody(body, true)
    if (validationError) return response({ error: validationError }, 400)
    const owned = await db.from('profiles').select('id', { count: 'exact', head: true }).eq('user_id', current.id)
    if (owned.error) return response({ error: 'database error' }, 500)
    if ((owned.count ?? 0) >= 32) return response({ error: 'profile limit reached' }, 400)
    const result = await db.from('profiles').insert({ user_id: current.id, name: body.name.trim(), avatar: body.avatar ?? null, settings: body.settings ?? {} }).select('id,name,avatar,settings,updated_at').single()
    return result.error ? response({ error: result.error.message }, 400) : response(result.data, 201)
  }
  if (!profileId || !(await profileContext(request, profileId))) return response({ error: 'unauthorized' }, 401)
  if (request.method === 'PATCH') {
    const body = await request.json()
    const validationError = validateProfileBody(body, false)
    if (validationError) return response({ error: validationError }, 400)
    const patch: Record<string, unknown> = { updated_at: new Date().toISOString() }
    if (body.name !== undefined) patch.name = body.name.trim()
    if (body.avatar !== undefined) patch.avatar = body.avatar ?? null
    if (body.settings !== undefined) patch.settings = body.settings ?? {}
    const result = await db.from('profiles').update(patch).eq('id', profileId).select('id,name,avatar,settings,updated_at').single()
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
    if (parts.at(-1) === 'tv-login' && request.method === 'GET') return deviceLoginPage(request)
    if (parts.at(-2) === 'auth') {
      const result = await auth(request, parts.at(-1)!)
      if (!result || result.error) return response({ error: result?.error?.message ?? 'unsupported auth action' }, 400)
      return response(result.data)
    }
    if (parts.at(-2) === 'device') return deviceAuth(request, parts.at(-1)!)
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
