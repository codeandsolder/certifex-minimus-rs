use std::{collections::BTreeMap, sync::Arc};

use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    routing::{get, post},
};
use certifex_core::{NodeRegistration, RegistrationResponse};
use clap::Parser;
use tokio::sync::RwLock;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(version, about = "Certifex registrar and certificate control plane")]
struct Args {
    #[arg(long, default_value = "127.0.0.1:7443")]
    listen: String,
}

#[derive(Clone, Default)]
struct AppState {
    registrations: Arc<RwLock<BTreeMap<String, NodeRegistration>>>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let args = Args::parse();
    let state = AppState::default();
    let app = Router::new()
        .route("/healthz", get(health))
        .route("/v1/register", post(register))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&args.listen).await?;
    info!(listen = %args.listen, "certifex-senex listening");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health() -> StatusCode {
    StatusCode::OK
}

async fn register(
    State(state): State<AppState>,
    Json(registration): Json<NodeRegistration>,
) -> Result<Json<RegistrationResponse>, (StatusCode, String)> {
    if let Err(error) = registration.validate() {
        warn!(node_id = %registration.node_id, %error, "rejected registration");
        return Err((StatusCode::BAD_REQUEST, error.to_string()));
    }

    let node_id = registration.node_id.clone();
    let names = registration.hostnames.len();
    state
        .registrations
        .write()
        .await
        .insert(node_id.clone(), registration);
    info!(%node_id, names, "registered node");

    Ok(Json(RegistrationResponse { certificate: None }))
}
