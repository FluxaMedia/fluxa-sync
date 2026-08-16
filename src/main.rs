use axum::{extract::State, http::StatusCode, response::IntoResponse, routing::get, Json, Router};
use serde::Serialize;
use sqlx::PgPool;
use std::{env, net::SocketAddr, sync::Arc};

#[derive(Clone)]
struct AppState {
    db: PgPool,
    jwt_secret: Arc<String>,
}

#[derive(Serialize)]
struct Health {
    status: &'static str,
    database: &'static str,
}

async fn health(State(state): State<AppState>) -> impl IntoResponse {
    let database = if sqlx::query("select 1").execute(&state.db).await.is_ok() { "ok" } else { "error" };
    (StatusCode::OK, Json(Health { status: "ok", database }))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let database_url = env::var("DATABASE_URL")?;
    let jwt_secret = env::var("JWT_SECRET")?;
    if jwt_secret.len() < 32 {
        return Err("JWT_SECRET must contain at least 32 characters".into());
    }
    let db = PgPool::connect(&database_url).await?;
    sqlx::migrate!().run(&db).await?;
    let state = AppState { db, jwt_secret: Arc::new(jwt_secret) };
    let app = Router::new().route("/health", get(health)).with_state(state);
    let address: SocketAddr = format!("0.0.0.0:{}", env::var("PORT").unwrap_or_else(|_| "8080".into())).parse()?;
    let listener = tokio::net::TcpListener::bind(address).await?;
    tracing::info!(%address, "fluxa-sync listening");
    axum::serve(listener, app).await?;
    Ok(())
}

