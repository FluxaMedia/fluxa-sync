use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use axum::{Json, Router, extract::{Query, State}, http::{HeaderMap, StatusCode}, response::{IntoResponse, Response}, routing::{get, post}};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{PgPool, Row};
use std::{env, net::SocketAddr, sync::Arc};
use uuid::Uuid;

#[derive(Clone)]
struct AppState {
    db: PgPool,
    jwt_secret: Arc<String>,
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
struct CreateProfile {
    name: String,
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
}

#[derive(Deserialize)]
struct SyncQuery {
    profile_id: Uuid,
    since: Option<i64>,
}

struct ApiError(StatusCode, String);

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self { Self(StatusCode::BAD_REQUEST, message.into()) }
    fn unauthorized() -> Self { Self(StatusCode::UNAUTHORIZED, "unauthorized".into()) }
    fn internal(error: impl ToString) -> Self { Self(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()) }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response { (self.0, Json(json!({"error": self.1}))).into_response() }
}

fn token_for(user_id: Uuid, secret: &str) -> Result<String, ApiError> {
    let claims = Claims { sub: user_id.to_string(), exp: (chrono::Utc::now().timestamp() + 60 * 60 * 24 * 30) as usize };
    encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_bytes())).map_err(ApiError::internal)
}

fn authenticated_user(headers: &HeaderMap, secret: &str) -> Result<Uuid, ApiError> {
    let value = headers.get("authorization").and_then(|value| value.to_str().ok()).ok_or_else(ApiError::unauthorized)?;
    let token = value.strip_prefix("Bearer ").ok_or_else(ApiError::unauthorized)?;
    let claims = decode::<Claims>(token, &DecodingKey::from_secret(secret.as_bytes()), &Validation::default()).map_err(|_| ApiError::unauthorized())?;
    Uuid::parse_str(&claims.claims.sub).map_err(|_| ApiError::unauthorized())
}

async fn health(State(state): State<AppState>) -> impl IntoResponse {
    let database = if sqlx::query("select 1").execute(&state.db).await.is_ok() { "ok" } else { "error" };
    (StatusCode::OK, Json(Health { status: "ok", database }))
}

async fn register(State(state): State<AppState>, Json(input): Json<Credentials>) -> Result<Json<Value>, ApiError> {
    if input.email.trim().is_empty() || input.password.len() < 8 { return Err(ApiError::bad_request("email and an 8 character password are required")); }
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default().hash_password(input.password.as_bytes(), &salt).map_err(ApiError::internal)?.to_string();
    let row = sqlx::query("insert into users (email, password_hash) values ($1, $2) returning id, email, created_at")
        .bind(input.email.trim().to_ascii_lowercase()).bind(hash).fetch_one(&state.db).await.map_err(ApiError::internal)?;
    let user_id: Uuid = row.try_get("id").map_err(ApiError::internal)?;
    sqlx::query("insert into profiles (user_id, name) values ($1, $2)").bind(user_id).bind("Default").execute(&state.db).await.map_err(ApiError::internal)?;
    let token = token_for(user_id, &state.jwt_secret)?;
    Ok(Json(json!({"access_token": token, "token_type": "bearer", "user": {"id": user_id, "email": row.try_get::<String, _>("email").map_err(ApiError::internal)?, "created_at": row.try_get::<chrono::DateTime<chrono::Utc>, _>("created_at").map_err(ApiError::internal)?}})))
}

async fn login(State(state): State<AppState>, Json(input): Json<Credentials>) -> Result<Json<Value>, ApiError> {
    let row = sqlx::query("select id, email, password_hash, created_at from users where email = $1")
        .bind(input.email.trim().to_ascii_lowercase()).fetch_optional(&state.db).await.map_err(ApiError::internal)?.ok_or_else(ApiError::unauthorized)?;
    let hash: String = row.try_get("password_hash").map_err(ApiError::internal)?;
    let parsed = PasswordHash::new(&hash).map_err(ApiError::internal)?;
    Argon2::default().verify_password(input.password.as_bytes(), &parsed).map_err(|_| ApiError::unauthorized())?;
    let user_id: Uuid = row.try_get("id").map_err(ApiError::internal)?;
    Ok(Json(json!({"access_token": token_for(user_id, &state.jwt_secret)?, "token_type": "bearer", "user": {"id": user_id, "email": row.try_get::<String, _>("email").map_err(ApiError::internal)?, "created_at": row.try_get::<chrono::DateTime<chrono::Utc>, _>("created_at").map_err(ApiError::internal)?}})))
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
    if input.name.trim().is_empty() { return Err(ApiError::bad_request("profile name is required")); }
    let row = sqlx::query("insert into profiles (user_id, name, avatar, settings) values ($1, $2, $3, $4) returning id, name, avatar, settings, updated_at")
        .bind(user_id).bind(input.name.trim()).bind(input.avatar).bind(input.settings.unwrap_or_else(|| json!({}))).fetch_one(&state.db).await.map_err(ApiError::internal)?;
    Ok(Json(json!({"id": row.try_get::<Uuid, _>("id").map_err(ApiError::internal)?, "name": row.try_get::<String, _>("name").map_err(ApiError::internal)?, "avatar": row.try_get::<Option<String>, _>("avatar").map_err(ApiError::internal)?, "settings": row.try_get::<Value, _>("settings").map_err(ApiError::internal)?, "updated_at": row.try_get::<chrono::DateTime<chrono::Utc>, _>("updated_at").map_err(ApiError::internal)?})))
}

async fn owns_profile(state: &AppState, user_id: Uuid, profile_id: Uuid) -> Result<(), ApiError> {
    let exists = sqlx::query("select 1 from profiles where id = $1 and user_id = $2").bind(profile_id).bind(user_id).fetch_optional(&state.db).await.map_err(ApiError::internal)?.is_some();
    if exists { Ok(()) } else { Err(ApiError::unauthorized()) }
}

async fn snapshot(State(state): State<AppState>, headers: HeaderMap, Query(query): Query<SyncQuery>) -> Result<Json<Value>, ApiError> {
    let user_id = authenticated_user(&headers, &state.jwt_secret)?;
    owns_profile(&state, user_id, query.profile_id).await?;
    let rows = sqlx::query("select entity_type, document_key, payload, deleted, revision, updated_at from sync_documents where profile_id = $1 order by revision")
        .bind(query.profile_id).fetch_all(&state.db).await.map_err(ApiError::internal)?;
    let documents = rows.into_iter().map(|row| json!({"entity_type": row.try_get::<String, _>("entity_type").unwrap_or_default(), "key": row.try_get::<String, _>("document_key").unwrap_or_default(), "payload": row.try_get::<Value, _>("payload").unwrap_or(Value::Null), "deleted": row.try_get::<bool, _>("deleted").unwrap_or(false), "revision": row.try_get::<i64, _>("revision").unwrap_or_default(), "updated_at": row.try_get::<chrono::DateTime<chrono::Utc>, _>("updated_at").unwrap_or_else(|_| chrono::Utc::now())})).collect::<Vec<_>>();
    Ok(Json(json!({"profile_id": query.profile_id, "documents": documents})))
}

async fn pull(State(state): State<AppState>, headers: HeaderMap, Query(query): Query<SyncQuery>) -> Result<Json<Value>, ApiError> {
    let user_id = authenticated_user(&headers, &state.jwt_secret)?;
    owns_profile(&state, user_id, query.profile_id).await?;
    let since = query.since.unwrap_or(0);
    let rows = sqlx::query("select entity_type, document_key, payload, deleted, revision, updated_at from sync_documents where profile_id = $1 and revision > $2 order by revision")
        .bind(query.profile_id).bind(since).fetch_all(&state.db).await.map_err(ApiError::internal)?;
    let changes = rows.into_iter().map(|row| json!({"entity_type": row.try_get::<String, _>("entity_type").unwrap_or_default(), "key": row.try_get::<String, _>("document_key").unwrap_or_default(), "payload": row.try_get::<Value, _>("payload").unwrap_or(Value::Null), "revision": row.try_get::<i64, _>("revision").unwrap_or_default(), "deleted": row.try_get::<bool, _>("deleted").unwrap_or(false), "updated_at": row.try_get::<chrono::DateTime<chrono::Utc>, _>("updated_at").unwrap_or_else(|_| chrono::Utc::now())})).collect::<Vec<_>>();
    let cursor = changes.last().and_then(|item| item.get("revision")).cloned().unwrap_or(json!(since));
    Ok(Json(json!({"profile_id": query.profile_id, "since": since, "cursor": cursor, "changes": changes})))
}

async fn push(State(state): State<AppState>, headers: HeaderMap, Json(input): Json<PushRequest>) -> Result<Json<Value>, ApiError> {
    let user_id = authenticated_user(&headers, &state.jwt_secret)?;
    owns_profile(&state, user_id, input.profile_id).await?;
    let mut transaction = state.db.begin().await.map_err(ApiError::internal)?;
    let mut applied = Vec::new();
    for change in input.changes {
        if change.entity_type.trim().is_empty() || change.key.trim().is_empty() { return Err(ApiError::bad_request("entity_type and key are required")); }
        let payload = change.payload.unwrap_or(Value::Null);
        let row = sqlx::query("insert into sync_documents (profile_id, document_type, document_key, payload, deleted, revision) values ($1, $2, $3, $4, $5, 1) on conflict (profile_id, document_type, document_key) do update set payload = excluded.payload, deleted = excluded.deleted, revision = sync_documents.revision + 1, updated_at = now() returning revision, updated_at")
            .bind(input.profile_id).bind(change.entity_type).bind(change.key).bind(payload).bind(change.deleted.unwrap_or(false)).fetch_one(&mut *transaction).await.map_err(ApiError::internal)?;
        applied.push(json!({"revision": row.try_get::<i64, _>("revision").map_err(ApiError::internal)?, "updated_at": row.try_get::<chrono::DateTime<chrono::Utc>, _>("updated_at").map_err(ApiError::internal)?}));
    }
    transaction.commit().await.map_err(ApiError::internal)?;
    Ok(Json(json!({"profile_id": input.profile_id, "applied": applied})))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let database_url = env::var("DATABASE_URL")?;
    let jwt_secret = env::var("JWT_SECRET")?;
    if jwt_secret.len() < 32 { return Err("JWT_SECRET must contain at least 32 characters".into()); }
    let db = PgPool::connect(&database_url).await?;
    sqlx::migrate!().run(&db).await?;
    let state = AppState { db, jwt_secret: Arc::new(jwt_secret) };
    let app = Router::new()
        .route("/health", get(health))
        .route("/api/v1/auth/register", post(register))
        .route("/api/v1/auth/login", post(login))
        .route("/api/v1/auth/me", get(me))
        .route("/api/v1/profiles", get(profiles).post(create_profile))
        .route("/api/v1/sync/snapshot", get(snapshot))
        .route("/api/v1/sync/pull", get(pull))
        .route("/api/v1/sync/push", post(push))
        .with_state(state);
    let address: SocketAddr = format!("0.0.0.0:{}", env::var("PORT").unwrap_or_else(|_| "8080".into())).parse()?;
    let listener = tokio::net::TcpListener::bind(address).await?;
    tracing::info!(%address, "fluxa-sync listening");
    axum::serve(listener, app).await?;
    Ok(())
}
