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
    seed_clients(&store).await?;

    let signer = Signer::Local(load_or_generate_dev_key(Path::new(".dev/signing-key.pem"))?);
    let state = AppState::new(cfg, store, signer, Mailer::Stdout(StdoutMailer::default()))?;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:8787").await?;
    tracing::info!("auth-service listening on http://127.0.0.1:8787");
    axum::serve(listener, auth_service::build_router(state)).await?;
    Ok(())
}

/// Seeds config/clients.json (when present) plus a fixed dev client for a
/// local RP on :5174.
async fn seed_clients(
    store: &auth_service::store::Store,
) -> Result<(), Box<dyn std::error::Error>> {
    #[derive(serde::Deserialize)]
    struct ClientsFile {
        clients: Vec<auth_service::domain::oauth::OidcClient>,
    }

    let path = std::env::var("CLIENTS_FILE").unwrap_or_else(|_| "config/clients.json".to_string());
    match std::fs::read_to_string(&path) {
        Ok(raw) => {
            let file: ClientsFile = serde_json::from_str(&raw)?;
            for client in &file.clients {
                store.put_client(client).await?;
                tracing::info!(client_id = %client.client_id, "seeded client");
            }
        }
        Err(_) => tracing::warn!(path, "clients file not found; skipping"),
    }

    let dev_client = auth_service::domain::oauth::OidcClient {
        client_id: "dev".to_string(),
        client_name: "Local dev RP".to_string(),
        redirect_uris: vec!["http://localhost:5174/callback".to_string()],
        post_logout_redirect_uris: vec!["http://localhost:5174/".to_string()],
        backchannel_logout_uri: None,
        allowed_origins: vec!["http://localhost:5174".to_string()],
        scopes: vec![
            "openid".to_string(),
            "email".to_string(),
            "offline_access".to_string(),
        ],
    };
    store.put_client(&dev_client).await?;
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
