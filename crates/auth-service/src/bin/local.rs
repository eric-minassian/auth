//! Local dev server: plain axum on 127.0.0.1:8787 against DynamoDB Local,
//! stdout email, and a persistent dev signing key. Browse the SPA via Vite at
//! http://auth.localhost:5173 (it proxies /api, /oauth, /.well-known here).

use std::path::Path;

use auth_service::config::AppConfig;
use auth_service::email::{Mailer, StdoutMailer};
use auth_service::jwt::{LocalSigner, Signer};
use auth_service::state::AppState;
use auth_service::store::{Store, schema};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,auth_service=debug".into()),
        )
        .init();

    let cfg = AppConfig::build(
        std::env::var("ISSUER").unwrap_or_else(|_| "http://auth.localhost:5173".to_string()),
        std::env::var("TABLE_NAME").unwrap_or_else(|_| "auth-local".to_string()),
        true,
        Some(
            std::env::var("DYNAMODB_ENDPOINT")
                .unwrap_or_else(|_| "http://127.0.0.1:8000".to_string()),
        ),
    )?;

    let aws = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new("us-east-1"))
        .credentials_provider(aws_sdk_dynamodb::config::Credentials::for_tests())
        .load()
        .await;
    let mut db_config = aws_sdk_dynamodb::config::Builder::from(&aws);
    if let Some(endpoint) = &cfg.dynamodb_endpoint {
        db_config = db_config.endpoint_url(endpoint);
    }
    let db = aws_sdk_dynamodb::Client::from_conf(db_config.build());
    schema::create_table_if_missing(&db, &cfg.table_name).await?;
    let store = Store::new(db, cfg.table_name.clone());

    let signer = Signer::Local(load_or_generate_dev_key(Path::new(".dev/signing-key.pem"))?);
    let state = AppState::new(cfg, store, signer, Mailer::Stdout(StdoutMailer::default()))?;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:8787").await?;
    tracing::info!("auth-service listening on http://127.0.0.1:8787");
    axum::serve(listener, auth_service::build_router(state)).await?;
    Ok(())
}

fn load_or_generate_dev_key(path: &Path) -> Result<LocalSigner, Box<dyn std::error::Error>> {
    if path.exists() {
        return Ok(LocalSigner::from_pem(&std::fs::read_to_string(path)?)?);
    }
    let signer = LocalSigner::generate();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, signer.to_pem()?)?;
    tracing::info!(path = %path.display(), "generated dev signing key");
    Ok(signer)
}
