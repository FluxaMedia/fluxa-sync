use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use axum::{Json, Router, extract::{ConnectInfo, DefaultBodyLimit, Query, Request, State, WebSocketUpgrade, ws::Message}, http::{HeaderMap, StatusCode, header}, middleware::{self, Next}, response::{IntoResponse, Response}, routing::{get, patch, post}};
use futures_util::{SinkExt, StreamExt};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row, postgres::{PgConnectOptions, PgPoolOptions}};
use std::{collections::HashMap, env, net::{IpAddr, SocketAddr}, str::FromStr, sync::{Arc, Mutex}, time::Instant};
use tokio::sync::broadcast;
use tower_http::cors::{Any, CorsLayer};
use uuid::Uuid;

const ENTITY_TYPES: [&str; 7] = ["library", "watch_progress", "watched_history", "collections", "addons", "plugins", "settings"];
const MAX_CHANGES: usize = 1000;
const MAX_KEY_BYTES: usize = 512;
const MAX_PAYLOAD_BYTES: usize = 512_000;
const MAX_PULL_CHANGES: usize = 2000;
const MAX_PROFILES_PER_USER: i64 = 32;

#[derive(Clone)]
struct SyncNotification {
    user_id: Uuid,
    message: Arc<str>,
}

#[derive(Clone)]
struct AppState {
    db: PgPool,
    jwt_secret: Arc<String>,
    events: broadcast::Sender<SyncNotification>,
    auth_limiter: Arc<RateLimiter>,
    sync_limiter: Arc<RateLimiter>,
    access_token_ttl: i64,
    trust_proxy_headers: bool,
}

struct Bucket {
    tokens: f64,
    last: Instant,
}

struct RateLimiter {
    buckets: Mutex<HashMap<String, Bucket>>,
    rate: f64,
    burst: f64,
}

impl RateLimiter {
    fn new(rate: f64, burst: f64) -> Self {
        Self { buckets: Mutex::new(HashMap::new()), rate, burst: burst.max(rate) }
    }

    fn allow(&self, key: &str) -> bool {
        let now = Instant::now();
        let mut buckets = match self.buckets.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if buckets.len() > 20_000 {
            buckets.retain(|_, bucket| now.duration_since(bucket.last).as_secs() < 600);
        }
        let bucket = buckets.entry(key.to_string()).or_insert(Bucket { tokens: self.burst, last: now });
        bucket.tokens = (bucket.tokens + now.duration_since(bucket.last).as_secs_f64() * self.rate).min(self.burst);
        bucket.last = now;
        if bucket.tokens < 1.0 {
            return false;
        }
        bucket.tokens -= 1.0;
        true
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

#[derive(Serialize)]
struct Health {
    status: &'static str,
    database: &'static str,
}

#[derive(Deserialize)]
struct Credentials {
    email: String,
    password: String,
}

#[derive(Deserialize)]
struct RefreshRequest {
    refresh_token: String,
}

#[derive(Deserialize)]
struct CreateProfile {
    name: String,
    avatar: Option<String>,
    settings: Option<Value>,
}

#[derive(Deserialize)]
struct UpdateProfile {
    name: Option<String>,
    avatar: Option<String>,
    settings: Option<Value>,
}

#[derive(Deserialize)]
struct PushRequest {
    profile_id: Uuid,
    changes: Vec<SyncChange>,
}

#[derive(Deserialize)]
struct SyncChange {
    entity_type: String,
    key: String,
    payload: Option<Value>,
    deleted: Option<bool>,
    expected_revision: Option<i64>,
}

#[derive(Deserialize)]
struct SyncQuery {
    profile_id: Uuid,
    since: Option<i64>,
}

fn hash_refresh_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn sensitive_key(key: &str) -> bool {
    let normalized: String = key.chars().filter(|c| *c != '_' && *c != '-').flat_map(|c| c.to_lowercase()).collect();
    ["accesstoken", "refreshtoken", "apikey", "secret", "password", "passwd", "authorization", "pinhash", "stremiotoken"]
        .iter()
        .any(|suffix| normalized.ends_with(suffix))
}

fn sensitive_path(value: &Value, path: &str) -> Option<String> {
    match value {
        Value::Array(entries) => entries.iter().enumerate().find_map(|(index, entry)| sensitive_path(entry, &format!("{path}[{index}]"))),
        Value::Object(fields) => fields.iter().find_map(|(key, child)| {
            if sensitive_key(key) {
                Some(format!("{path}.{key}"))
            } else {
                sensitive_path(child, &format!("{path}.{key}"))
            }
        }),
        _ => None,
    }
}

fn valid_http_url(value: Option<&Value>) -> bool {
    let Some(Value::String(text)) = value else { return false };
    if text.len() > 2048 {
        return false;
    }
    let Some(rest) = text.strip_prefix("http://").or_else(|| text.strip_prefix("https://")) else { return false };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    !authority.is_empty() && !authority.contains('@')
}

fn validate_entity_payload(entity: &str, payload: &Value) -> Option<&'static str> {
    if !payload.is_object() && !payload.is_array() {
        return Some("payload must be an object or array");
    }
    match entity {
        "addons" => {
            let entries = payload.as_array()?;
            if entries.len() > 500 {
                return Some("addons payload must be an array of at most 500 items");
            }
            for addon in entries {
                let Some(item) = addon.as_object() else { return Some("each addon must be an object") };
                match item.get("manifest") {
                    Some(manifest) => {
                        if !manifest.get("id").is_some_and(Value::is_string) || !manifest.get("name").is_some_and(Value::is_string) {
                            return Some("addon manifest id and name are required");
                        }
                    }
                    None => {
                        if !item.get("name").is_some_and(Value::is_string) {
                            return Some("normalized addon name is required");
                        }
                    }
                }
                if !valid_http_url(item.get("transportUrl").or_else(|| item.get("url"))) {
                    return Some("addon URL must be an http(s) URL without credentials");
                }
            }
            None
        }
        "plugins" => {
            let repositories = payload.get("repositoryUrls").and_then(Value::as_array);
            match repositories {
                Some(urls) if urls.len() <= 200 && urls.iter().all(|url| valid_http_url(Some(url))) => {}
                _ => return Some("plugins.repositoryUrls must contain only http(s) URLs without credentials"),
            }
            let overrides = payload.get("scraperOverrides");
            match overrides.and_then(Value::as_object) {
                Some(entries) if entries.values().all(Value::is_boolean) => None,
                Some(_) => Some("plugins.scraperOverrides values must be boolean"),
                None => Some("plugins.scraperOverrides must be an object"),
            }
        }
        "library" => {
            let status = payload.get("status").and_then(Value::as_str).unwrap_or("");
            if !["watchlist", "completed", "dropped"].contains(&status) {
                return Some("library status is invalid");
            }
            let item = payload.get("item");
            if !item.and_then(|value| value.get("id")).is_some_and(Value::is_string)
                || !item.and_then(|value| value.get("type")).is_some_and(Value::is_string)
            {
                return Some("library item id and type are required");
            }
            None
        }
        "watched_history" => {
            const ALLOWED: [&str; 6] = ["watched", "contentType", "videoId", "season", "episode", "lastWatched"];
            let fields = payload.as_object()?;
            if fields.keys().any(|key| !ALLOWED.contains(&key.as_str())) {
                return Some("watched history metadata is not allowed");
            }
            match fields.get("contentType") {
                Some(value) if !value.is_string() => Some("watched history contentType must be a string"),
                _ => None,
            }
        }
        "watch_progress" => {
            const ALLOWED: [&str; 12] = [
                "contentId", "contentType", "videoId", "season", "episode", "position",
                "duration", "lastWatched", "progressKey", "lastAudioLanguage", "lastSubtitleLanguage", "lastStreamIndex",
            ];
            let fields = payload.as_object()?;
            if fields.keys().any(|key| !ALLOWED.contains(&key.as_str())) {
                return Some("watch progress metadata is not allowed");
            }
            if !fields.get("contentId").is_some_and(Value::is_string)
                || !fields.get("contentType").is_some_and(Value::is_string)
                || !fields.get("position").is_some_and(Value::is_number)
                || !fields.get("duration").is_some_and(Value::is_number)
            {
                return Some("watch progress identity and timing are required");
            }
            None
        }
        "settings" => {
            let fields = payload.as_object()?;
            if fields.contains_key("profile") {
                return Some("profile settings must use key profile, not a nested profile payload");
            }
            if fields.get("name").is_some_and(|value| !value.is_string()) {
                return Some("profile name must be a string");
            }
            match fields.get("avatarUrl") {
                Some(Value::Null) | None => {}
                value => {
                    if !valid_http_url(value) {
                        return Some("profile avatarUrl must be an http(s) URL");
                    }
                }
            }
            if ["usesPrimaryAddons", "usesPrimaryPlugins"].iter().any(|key| fields.get(*key).is_some_and(|value| !value.is_boolean())) {
                return Some("usesPrimaryAddons and usesPrimaryPlugins must be boolean");
            }
            None
        }
        _ => None,
    }
}

fn validate_change(change: &SyncChange) -> Option<String> {
    if !ENTITY_TYPES.contains(&change.entity_type.as_str()) {
        return Some("unsupported entity_type".into());
    }
    if change.key.is_empty() || change.key.len() > MAX_KEY_BYTES {
        return Some("invalid document key".into());
    }
    if change.expected_revision.is_some_and(|revision| revision < 0) {
        return Some("expected_revision must be a non-negative integer".into());
    }
    if let Some(payload) = &change.payload {
        if let Some(found) = sensitive_path(payload, "payload") {
            return Some(format!("sensitive field is not allowed: {found}"));
        }
    }
    if change.deleted.unwrap_or(false) {
        return match &change.payload {
            None | Some(Value::Null) => None,
            Some(_) => Some("deleted changes must not include a payload".into()),
        };
    }
    let payload = change.payload.as_ref().unwrap_or(&Value::Null);
    if serde_json::to_string(payload).map(|text| text.len()).unwrap_or(usize::MAX) > MAX_PAYLOAD_BYTES {
        return Some("payload is too large".into());
    }
    validate_entity_payload(&change.entity_type, payload).map(str::to_string)
}

fn valid_email(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() < 3 || trimmed.len() > 320 || trimmed.contains(char::is_whitespace) {
        return false;
    }
    let mut parts = trimmed.split('@');
    let (Some(local), Some(domain), None) = (parts.next(), parts.next(), parts.next()) else { return false };
    !local.is_empty() && domain.contains('.') && !domain.starts_with('.') && !domain.ends_with('.')
}

fn client_address(headers: &HeaderMap, peer: SocketAddr, trust_proxy_headers: bool) -> String {
    if trust_proxy_headers {
        for name in ["x-forwarded-for", "x-real-ip"] {
            let candidate = headers
                .get(name)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.split(',').next())
                .map(str::trim)
                .filter(|value| value.parse::<IpAddr>().is_ok());
            if let Some(address) = candidate {
                return address.to_string();
            }
        }
    }
    peer.ip().to_string()
}

async fn compact_events(db: &PgPool, retention_days: i32) {
    let result = sqlx::query("delete from sync_events where created_at < now() - ($1::double precision * interval '1 day')")
        .bind(retention_days.max(1)).execute(db).await;
    if let Ok(result) = result {
        if result.rows_affected() > 0 { tracing::info!(removed = result.rows_affected(), retention_days, "compacted sync events"); }
    }
}

struct ApiError(StatusCode, String);

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self { Self(StatusCode::BAD_REQUEST, message.into()) }
    fn unauthorized() -> Self { Self(StatusCode::UNAUTHORIZED, "unauthorized".into()) }
    fn throttled() -> Self { Self(StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded".into()) }
    fn internal(error: impl ToString) -> Self {
        tracing::error!(error = %error.to_string(), "request failed");
        Self(StatusCode::INTERNAL_SERVER_ERROR, "internal error".into())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response { (self.0, Json(json!({"error": self.1}))).into_response() }
}

fn token_for(user_id: Uuid, secret: &str, ttl: i64) -> Result<String, ApiError> {
    let claims = Claims { sub: user_id.to_string(), exp: (chrono::Utc::now().timestamp() + ttl) as usize };
    encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_bytes())).map_err(ApiError::internal)
}

async fn session(state: &AppState, user_id: Uuid, email: String, created_at: chrono::DateTime<chrono::Utc>) -> Result<Json<Value>, ApiError> {
    let access_token = token_for(user_id, &state.jwt_secret, state.access_token_ttl)?;
    let refresh_token = Uuid::new_v4().to_string();
    sqlx::query("insert into refresh_tokens (user_id, token, expires_at) values ($1, $2, now() + interval '90 days')")
        .bind(user_id).bind(hash_refresh_token(&refresh_token)).execute(&state.db).await.map_err(ApiError::internal)?;
    Ok(Json(json!({"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer", "expires_in": state.access_token_ttl, "user": {"id": user_id, "email": email, "created_at": created_at}})))
}

fn authenticated_user(headers: &HeaderMap, secret: &str) -> Result<Uuid, ApiError> {
    let value = headers.get("authorization").and_then(|value| value.to_str().ok()).ok_or_else(ApiError::unauthorized)?;
    let token = value.strip_prefix("Bearer ").ok_or_else(ApiError::unauthorized)?;
    let claims = decode::<Claims>(token, &DecodingKey::from_secret(secret.as_bytes()), &Validation::default()).map_err(|_| ApiError::unauthorized())?;
    Uuid::parse_str(&claims.claims.sub).map_err(|_| ApiError::unauthorized())
}

async fn throttle_auth(State(state): State<AppState>, ConnectInfo(peer): ConnectInfo<SocketAddr>, request: Request, next: Next) -> Response {
    let address = client_address(request.headers(), peer, state.trust_proxy_headers);
    if !state.auth_limiter.allow(&address) {
        return ApiError::throttled().into_response();
    }
    next.run(request).await
}

async fn health(State(state): State<AppState>) -> impl IntoResponse {
    let database = if sqlx::query("select 1").execute(&state.db).await.is_ok() { "ok" } else { "error" };
    (StatusCode::OK, Json(Health { status: "ok", database }))
}

async fn register(State(state): State<AppState>, Json(input): Json<Credentials>) -> Result<Json<Value>, ApiError> {
    if !valid_email(&input.email) || input.password.len() < 8 || input.password.len() > 1024 {
        return Err(ApiError::bad_request("a valid email and an 8 character password are required"));
    }
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default().hash_password(input.password.as_bytes(), &salt).map_err(ApiError::internal)?.to_string();
    let row = sqlx::query("insert into users (email, password_hash) values ($1, $2) returning id, email, created_at")
        .bind(input.email.trim().to_ascii_lowercase()).bind(hash).fetch_one(&state.db).await.map_err(ApiError::internal)?;
    let user_id: Uuid = row.try_get("id").map_err(ApiError::internal)?;
    sqlx::query("insert into profiles (user_id, name) values ($1, $2)").bind(user_id).bind("Default").execute(&state.db).await.map_err(ApiError::internal)?;
    session(&state, user_id, row.try_get::<String, _>("email").map_err(ApiError::internal)?, row.try_get::<chrono::DateTime<chrono::Utc>, _>("created_at").map_err(ApiError::internal)?).await
}

async fn login(State(state): State<AppState>, Json(input): Json<Credentials>) -> Result<Json<Value>, ApiError> {
    let found = sqlx::query("select id, email, password_hash, created_at from users where email = $1")
        .bind(input.email.trim().to_ascii_lowercase()).fetch_optional(&state.db).await.map_err(ApiError::internal)?;
    let Some(row) = found else {
        let salt = SaltString::generate(&mut OsRng);
        let _ = Argon2::default().hash_password(input.password.as_bytes(), &salt);
        return Err(ApiError::unauthorized());
    };
    let hash: String = row.try_get("password_hash").map_err(ApiError::internal)?;
    let parsed = PasswordHash::new(&hash).map_err(ApiError::internal)?;
    Argon2::default().verify_password(input.password.as_bytes(), &parsed).map_err(|_| ApiError::unauthorized())?;
    let user_id: Uuid = row.try_get("id").map_err(ApiError::internal)?;
    session(&state, user_id, row.try_get::<String, _>("email").map_err(ApiError::internal)?, row.try_get::<chrono::DateTime<chrono::Utc>, _>("created_at").map_err(ApiError::internal)?).await
}

async fn refresh(State(state): State<AppState>, Json(input): Json<RefreshRequest>) -> Result<Json<Value>, ApiError> {
    let presented = hash_refresh_token(&input.refresh_token);
    let row = sqlx::query("select u.id, u.email, u.created_at from refresh_tokens r join users u on u.id = r.user_id where r.token = $1 and r.revoked_at is null and r.expires_at > now()")
        .bind(&presented).fetch_optional(&state.db).await.map_err(ApiError::internal)?;
    let Some(row) = row else {
        let reused: Option<Uuid> = sqlx::query("select user_id from refresh_tokens where token = $1")
            .bind(&presented).fetch_optional(&state.db).await.map_err(ApiError::internal)?
            .and_then(|row| row.try_get("user_id").ok());
        if let Some(user_id) = reused {
            sqlx::query("update refresh_tokens set revoked_at = now() where user_id = $1 and revoked_at is null")
                .bind(user_id).execute(&state.db).await.map_err(ApiError::internal)?;
            tracing::warn!(%user_id, "revoked refresh token family after reuse");
        }
        return Err(ApiError::unauthorized());
    };
    sqlx::query("update refresh_tokens set revoked_at = now() where token = $1").bind(&presented).execute(&state.db).await.map_err(ApiError::internal)?;
    session(&state, row.try_get("id").map_err(ApiError::internal)?, row.try_get("email").map_err(ApiError::internal)?, row.try_get("created_at").map_err(ApiError::internal)?).await
}

async fn logout(State(state): State<AppState>, headers: HeaderMap, Json(input): Json<RefreshRequest>) -> Result<StatusCode, ApiError> {
    let user_id = authenticated_user(&headers, &state.jwt_secret)?;
    sqlx::query("update refresh_tokens set revoked_at = now() where token = $1 and user_id = $2")
        .bind(hash_refresh_token(&input.refresh_token)).bind(user_id).execute(&state.db).await.map_err(ApiError::internal)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn me(State(state): State<AppState>, headers: HeaderMap) -> Result<Json<Value>, ApiError> {
    let user_id = authenticated_user(&headers, &state.jwt_secret)?;
    let row = sqlx::query("select id, email, created_at from users where id = $1").bind(user_id).fetch_optional(&state.db).await.map_err(ApiError::internal)?.ok_or_else(ApiError::unauthorized)?;
    Ok(Json(json!({"id": row.try_get::<Uuid, _>("id").map_err(ApiError::internal)?, "email": row.try_get::<String, _>("email").map_err(ApiError::internal)?, "created_at": row.try_get::<chrono::DateTime<chrono::Utc>, _>("created_at").map_err(ApiError::internal)?})))
}

async fn profiles(State(state): State<AppState>, headers: HeaderMap) -> Result<Json<Value>, ApiError> {
    let user_id = authenticated_user(&headers, &state.jwt_secret)?;
    let rows = sqlx::query("select id, name, avatar, settings, updated_at from profiles where user_id = $1 order by updated_at, id").bind(user_id).fetch_all(&state.db).await.map_err(ApiError::internal)?;
    let profiles = rows.into_iter().map(|row| json!({"id": row.try_get::<Uuid, _>("id").unwrap_or_default(), "name": row.try_get::<String, _>("name").unwrap_or_default(), "avatar": row.try_get::<Option<String>, _>("avatar").unwrap_or(None), "settings": row.try_get::<Value, _>("settings").unwrap_or_else(|_| json!({})), "updated_at": row.try_get::<chrono::DateTime<chrono::Utc>, _>("updated_at").unwrap_or_else(|_| chrono::Utc::now())})).collect::<Vec<_>>();
    Ok(Json(json!(profiles)))
}

async fn create_profile(State(state): State<AppState>, headers: HeaderMap, Json(input): Json<CreateProfile>) -> Result<Json<Value>, ApiError> {
    let user_id = authenticated_user(&headers, &state.jwt_secret)?;
    let name = input.name.trim();
    if name.is_empty() || name.len() > 160 { return Err(ApiError::bad_request("profile name is required")); }
    if let Some(settings) = &input.settings {
        if let Some(found) = sensitive_path(settings, "settings") {
            return Err(ApiError::bad_request(format!("sensitive field is not allowed: {found}")));
        }
    }
    if input.avatar.is_some() && !valid_http_url(input.avatar.as_ref().map(|value| json!(value)).as_ref()) {
        return Err(ApiError::bad_request("profile avatar must be an http(s) URL without credentials"));
    }
    let count: i64 = sqlx::query("select count(*) as total from profiles where user_id = $1").bind(user_id)
        .fetch_one(&state.db).await.map_err(ApiError::internal)?.try_get("total").unwrap_or(0);
    if count >= MAX_PROFILES_PER_USER { return Err(ApiError::bad_request("profile limit reached")); }
    let row = sqlx::query("insert into profiles (user_id, name, avatar, settings) values ($1, $2, $3, $4) returning id, name, avatar, settings, updated_at")
        .bind(user_id).bind(name).bind(input.avatar).bind(input.settings.unwrap_or_else(|| json!({}))).fetch_one(&state.db).await.map_err(ApiError::internal)?;
    Ok(Json(json!({"id": row.try_get::<Uuid, _>("id").map_err(ApiError::internal)?, "name": row.try_get::<String, _>("name").map_err(ApiError::internal)?, "avatar": row.try_get::<Option<String>, _>("avatar").map_err(ApiError::internal)?, "settings": row.try_get::<Value, _>("settings").map_err(ApiError::internal)?, "updated_at": row.try_get::<chrono::DateTime<chrono::Utc>, _>("updated_at").map_err(ApiError::internal)?})))
}

async fn update_profile(State(state): State<AppState>, headers: HeaderMap, axum::extract::Path(profile_id): axum::extract::Path<Uuid>, Json(input): Json<UpdateProfile>) -> Result<Json<Value>, ApiError> {
    let user_id = authenticated_user(&headers, &state.jwt_secret)?;
    owns_profile(&state, user_id, profile_id).await?;
    if let Some(settings) = &input.settings {
        if let Some(found) = sensitive_path(settings, "settings") {
            return Err(ApiError::bad_request(format!("sensitive field is not allowed: {found}")));
        }
    }
    let row = sqlx::query("update profiles set name = coalesce($2, name), avatar = coalesce($3, avatar), settings = coalesce($4, settings), updated_at = now() where id = $1 returning id, name, avatar, settings, updated_at")
        .bind(profile_id).bind(input.name).bind(input.avatar).bind(input.settings).fetch_one(&state.db).await.map_err(ApiError::internal)?;
    Ok(Json(json!({"id": row.try_get::<Uuid, _>("id").map_err(ApiError::internal)?, "name": row.try_get::<String, _>("name").map_err(ApiError::internal)?, "avatar": row.try_get::<Option<String>, _>("avatar").map_err(ApiError::internal)?, "settings": row.try_get::<Value, _>("settings").map_err(ApiError::internal)?, "updated_at": row.try_get::<chrono::DateTime<chrono::Utc>, _>("updated_at").map_err(ApiError::internal)?})))
}

async fn delete_profile(State(state): State<AppState>, headers: HeaderMap, axum::extract::Path(profile_id): axum::extract::Path<Uuid>) -> Result<StatusCode, ApiError> {
    let user_id = authenticated_user(&headers, &state.jwt_secret)?;
    owns_profile(&state, user_id, profile_id).await?;
    let count = sqlx::query("delete from profiles where id = $1 and user_id = $2").bind(profile_id).bind(user_id).execute(&state.db).await.map_err(ApiError::internal)?.rows_affected();
    if count == 0 { return Err(ApiError::bad_request("profile not found")); }
    Ok(StatusCode::NO_CONTENT)
}

async fn owns_profile(state: &AppState, user_id: Uuid, profile_id: Uuid) -> Result<i64, ApiError> {
    let row = sqlx::query("select sync_revision from profiles where id = $1 and user_id = $2").bind(profile_id).bind(user_id)
        .fetch_optional(&state.db).await.map_err(ApiError::internal)?.ok_or_else(ApiError::unauthorized)?;
    row.try_get("sync_revision").map_err(ApiError::internal)
}

async fn snapshot(State(state): State<AppState>, headers: HeaderMap, Query(query): Query<SyncQuery>) -> Result<Json<Value>, ApiError> {
    let user_id = authenticated_user(&headers, &state.jwt_secret)?;
    let cursor = owns_profile(&state, user_id, query.profile_id).await?;
    if !state.sync_limiter.allow(&user_id.to_string()) { return Err(ApiError::throttled()); }
    let rows = sqlx::query("select entity_type, document_key, payload, deleted, revision, updated_at from sync_documents where profile_id = $1 order by revision")
        .bind(query.profile_id).fetch_all(&state.db).await.map_err(ApiError::internal)?;
    let documents = rows.into_iter().map(|row| json!({"entity_type": row.try_get::<String, _>("entity_type").unwrap_or_default(), "key": row.try_get::<String, _>("document_key").unwrap_or_default(), "payload": row.try_get::<Value, _>("payload").unwrap_or(Value::Null), "deleted": row.try_get::<bool, _>("deleted").unwrap_or(false), "revision": row.try_get::<i64, _>("revision").unwrap_or_default(), "updated_at": row.try_get::<chrono::DateTime<chrono::Utc>, _>("updated_at").unwrap_or_else(|_| chrono::Utc::now())})).collect::<Vec<_>>();
    Ok(Json(json!({"profile_id": query.profile_id, "cursor": cursor, "documents": documents})))
}

async fn pull(State(state): State<AppState>, headers: HeaderMap, Query(query): Query<SyncQuery>) -> Result<Json<Value>, ApiError> {
    let user_id = authenticated_user(&headers, &state.jwt_secret)?;
    let current_revision = owns_profile(&state, user_id, query.profile_id).await?;
    if !state.sync_limiter.allow(&user_id.to_string()) { return Err(ApiError::throttled()); }
    let since = query.since.unwrap_or(0);
    let (minimum_row, rows) = tokio::try_join!(
        sqlx::query("select min(revision) as revision from sync_events where profile_id = $1").bind(query.profile_id).fetch_one(&state.db),
        sqlx::query("select entity_type, document_key, payload, deleted, revision, created_at from sync_events where profile_id = $1 and revision > $2 order by revision limit $3")
            .bind(query.profile_id).bind(since).bind(MAX_PULL_CHANGES as i64).fetch_all(&state.db),
    ).map_err(ApiError::internal)?;
    let minimum = minimum_row.try_get::<Option<i64>, _>("revision").map_err(ApiError::internal)?;
    let reset_required = since > 0 && match minimum { Some(revision) => since < revision - 1, None => since < current_revision };
    let truncated = rows.len() == MAX_PULL_CHANGES;
    let changes = rows.into_iter().map(|row| json!({"entity_type": row.try_get::<String, _>("entity_type").unwrap_or_default(), "key": row.try_get::<String, _>("document_key").unwrap_or_default(), "payload": row.try_get::<Value, _>("payload").unwrap_or(Value::Null), "revision": row.try_get::<i64, _>("revision").unwrap_or_default(), "deleted": row.try_get::<bool, _>("deleted").unwrap_or(false), "updated_at": row.try_get::<chrono::DateTime<chrono::Utc>, _>("created_at").unwrap_or_else(|_| chrono::Utc::now())})).collect::<Vec<_>>();
    let cursor = match truncated {
        true => changes.last().and_then(|change| change.get("revision")).and_then(Value::as_i64).unwrap_or(current_revision),
        false => current_revision,
    };
    Ok(Json(json!({"profile_id": query.profile_id, "since": since, "cursor": cursor, "minimum_available_revision": minimum, "reset_required": reset_required, "has_more": truncated, "changes": changes})))
}

async fn push(State(state): State<AppState>, headers: HeaderMap, Json(input): Json<PushRequest>) -> Result<Json<Value>, ApiError> {
    let user_id = authenticated_user(&headers, &state.jwt_secret)?;
    if input.changes.len() > MAX_CHANGES {
        return Err(ApiError::bad_request("at most 1000 changes are allowed"));
    }
    for change in &input.changes {
        if let Some(message) = validate_change(change) {
            return Err(ApiError::bad_request(message));
        }
    }
    let profile_id = input.profile_id;
    owns_profile(&state, user_id, profile_id).await?;
    if !state.sync_limiter.allow(&user_id.to_string()) { return Err(ApiError::throttled()); }

    let mut transaction = state.db.begin().await.map_err(ApiError::internal)?;
    let current_revision: i64 = sqlx::query("select sync_revision from profiles where id = $1 for update").bind(profile_id)
        .fetch_one(&mut *transaction).await.map_err(ApiError::internal)?.try_get("sync_revision").map_err(ApiError::internal)?;

    let requested_types: Vec<String> = input.changes.iter().map(|change| change.entity_type.clone()).collect();
    let requested_keys: Vec<String> = input.changes.iter().map(|change| change.key.clone()).collect();
    let existing_rows = sqlx::query(
        "select document_type, document_key, revision from sync_documents where profile_id = $1 \
         and (document_type, document_key) in (select * from unnest($2::text[], $3::text[]))")
        .bind(profile_id).bind(&requested_types).bind(&requested_keys)
        .fetch_all(&mut *transaction).await.map_err(ApiError::internal)?;
    let mut existing: HashMap<(String, String), i64> = HashMap::new();
    for row in existing_rows {
        let identity = (row.try_get::<String, _>("document_type").unwrap_or_default(), row.try_get::<String, _>("document_key").unwrap_or_default());
        existing.insert(identity, row.try_get::<i64, _>("revision").unwrap_or(0));
    }

    let mut conflicts = Vec::new();
    let mut order: Vec<(String, String)> = Vec::new();
    let mut pending: HashMap<(String, String), (Value, bool)> = HashMap::new();
    for change in input.changes {
        let identity = (change.entity_type, change.key);
        if let Some(expected) = change.expected_revision {
            let actual = existing.get(&identity).copied().unwrap_or(0);
            if actual != expected {
                conflicts.push(json!({"entity_type": identity.0, "key": identity.1, "expected_revision": expected, "actual_revision": actual}));
                continue;
            }
        }
        if !pending.contains_key(&identity) { order.push(identity.clone()); }
        pending.insert(identity, (change.payload.unwrap_or(Value::Null), change.deleted.unwrap_or(false)));
    }

    let mut applied = Vec::new();
    let mut types = Vec::with_capacity(order.len());
    let mut keys = Vec::with_capacity(order.len());
    let mut payloads = Vec::with_capacity(order.len());
    let mut deletions = Vec::with_capacity(order.len());
    let mut revisions = Vec::with_capacity(order.len());
    for (index, identity) in order.into_iter().enumerate() {
        let Some((payload, deleted)) = pending.remove(&identity) else { continue };
        let revision = current_revision + index as i64 + 1;
        applied.push(json!({"revision": revision, "entity_type": identity.0, "key": identity.1, "deleted": deleted}));
        types.push(identity.0);
        keys.push(identity.1);
        payloads.push(payload);
        deletions.push(deleted);
        revisions.push(revision);
    }

    if !types.is_empty() {
        sqlx::query(
            "insert into sync_documents (profile_id, document_type, document_key, payload, deleted, revision) \
             select $1, entry.document_type, entry.document_key, entry.payload, entry.deleted, entry.revision \
             from unnest($2::text[], $3::text[], $4::jsonb[], $5::bool[], $6::bigint[]) \
             as entry(document_type, document_key, payload, deleted, revision) \
             on conflict (profile_id, document_type, document_key) do update set \
             payload = excluded.payload, deleted = excluded.deleted, revision = excluded.revision, updated_at = now()")
            .bind(profile_id).bind(&types).bind(&keys).bind(&payloads).bind(&deletions).bind(&revisions)
            .execute(&mut *transaction).await.map_err(ApiError::internal)?;
        sqlx::query(
            "insert into sync_events (profile_id, entity_type, document_key, payload, deleted, revision) \
             select $1, entry.entity_type, entry.document_key, entry.payload, entry.deleted, entry.revision \
             from unnest($2::text[], $3::text[], $4::jsonb[], $5::bool[], $6::bigint[]) \
             as entry(entity_type, document_key, payload, deleted, revision)")
            .bind(profile_id).bind(&types).bind(&keys).bind(&payloads).bind(&deletions).bind(&revisions)
            .execute(&mut *transaction).await.map_err(ApiError::internal)?;
    }

    let cursor = current_revision + applied.len() as i64;
    sqlx::query("update profiles set sync_revision = $2, updated_at = now() where id = $1").bind(profile_id).bind(cursor)
        .execute(&mut *transaction).await.map_err(ApiError::internal)?;
    transaction.commit().await.map_err(ApiError::internal)?;

    if !applied.is_empty() {
        let message: Arc<str> = Arc::from(json!({"profile_id": profile_id, "changes": applied}).to_string().as_str());
        let _ = state.events.send(SyncNotification { user_id, message });
    }
    Ok(Json(json!({"profile_id": profile_id, "applied": applied, "conflicts": conflicts, "cursor": cursor})))
}

async fn realtime(State(state): State<AppState>, headers: HeaderMap, ws: WebSocketUpgrade) -> Result<Response, ApiError> {
    let user_id = authenticated_user(&headers, &state.jwt_secret)?;
    let mut receiver = state.events.subscribe();
    Ok(ws.on_upgrade(move |socket| async move {
        let (mut sender, mut incoming) = socket.split();
        loop {
            tokio::select! {
                event = receiver.recv() => match event {
                    Ok(notification) => {
                        if notification.user_id != user_id { continue }
                        if sender.send(Message::Text(notification.message.as_ref().into())).await.is_err() { break }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(_) => break,
                },
                message = incoming.next() => match message {
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(_)) => {},
                    Some(Err(_)) => break,
                }
            }
        }
    }))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let database_url = env::var("DATABASE_URL")?;
    let jwt_secret = env::var("JWT_SECRET")?;
    if jwt_secret.len() < 32 { return Err("JWT_SECRET must contain at least 32 characters".into()); }
    let mut connect_options = PgConnectOptions::from_str(&database_url)?;
    if env::var("DATABASE_DISABLE_STATEMENT_CACHE").map(|value| value == "1").unwrap_or(false) {
        connect_options = connect_options.statement_cache_capacity(0);
    }
    let max_connections = env::var("DATABASE_MAX_CONNECTIONS").ok().and_then(|value| value.parse().ok()).unwrap_or(10);
    let db: PgPool = PgPoolOptions::new().max_connections(max_connections).connect_with(connect_options).await?;
    sqlx::migrate!().run(&db).await?;
    let (events, _) = broadcast::channel(256);
    let access_token_ttl = env::var("ACCESS_TOKEN_TTL_SECONDS").ok().and_then(|value| value.parse::<i64>().ok()).unwrap_or(3600).clamp(300, 86_400);
    let auth_rate = env::var("AUTH_REQUESTS_PER_MINUTE").ok().and_then(|value| value.parse::<f64>().ok()).unwrap_or(10.0).max(1.0);
    let sync_rate = env::var("SYNC_REQUESTS_PER_MINUTE").ok().and_then(|value| value.parse::<f64>().ok()).unwrap_or(120.0).max(1.0);
    let state = AppState {
        db,
        jwt_secret: Arc::new(jwt_secret),
        events,
        auth_limiter: Arc::new(RateLimiter::new(auth_rate / 60.0, auth_rate)),
        sync_limiter: Arc::new(RateLimiter::new(sync_rate / 60.0, sync_rate)),
        access_token_ttl,
        trust_proxy_headers: env::var("TRUST_PROXY_HEADERS").map(|value| value == "1" || value.eq_ignore_ascii_case("true")).unwrap_or(false),
    };
    let retention_days = env::var("SYNC_EVENT_RETENTION_DAYS").ok().and_then(|value| value.parse::<i32>().ok()).unwrap_or(30).max(1);
    let compaction_db = state.db.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60 * 60));
        loop {
            interval.tick().await;
            compact_events(&compaction_db, retention_days).await;
        }
    });
    let cors = match env::var("CORS_ALLOWED_ORIGINS") {
        Ok(value) if !value.trim().is_empty() && value.trim() != "*" => {
            let origins = value.split(',').filter_map(|origin| origin.trim().parse::<header::HeaderValue>().ok()).collect::<Vec<_>>();
            CorsLayer::new().allow_origin(origins).allow_methods(Any).allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
        }
        _ => CorsLayer::new().allow_origin(Any).allow_methods(Any).allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE]),
    };
    let auth = Router::new()
        .route("/api/v1/auth/register", post(register))
        .route("/api/v1/auth/login", post(login))
        .route("/api/v1/auth/refresh", post(refresh))
        .layer(middleware::from_fn_with_state(state.clone(), throttle_auth));
    let app = Router::new()
        .route("/health", get(health))
        .route("/api/v1/auth/logout", post(logout))
        .route("/api/v1/auth/me", get(me))
        .route("/api/v1/profiles", get(profiles).post(create_profile))
        .route("/api/v1/profiles/{profile_id}", patch(update_profile).delete(delete_profile))
        .route("/api/v1/sync/snapshot", get(snapshot))
        .route("/api/v1/sync/pull", get(pull))
        .route("/api/v1/sync/push", post(push).layer(DefaultBodyLimit::max(8 * 1024 * 1024)))
        .route("/api/v1/realtime", get(realtime))
        .merge(auth)
        .layer(cors)
        .with_state(state);
    let address: SocketAddr = format!("{}:{}", env::var("BIND_ADDRESS").unwrap_or_else(|_| "0.0.0.0".into()), env::var("PORT").unwrap_or_else(|_| "8080".into())).parse()?;
    let listener = tokio::net::TcpListener::bind(address).await?;
    tracing::info!(%address, "fluxa-sync listening");
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;
    Ok(())
}
