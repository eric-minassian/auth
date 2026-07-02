use auth_service::config::AppConfig;
use auth_service::jwt::{KmsSigner, LocalSigner, Signer};
use auth_service::state::AppState;
use auth_service::store::Store;
use lambda_http::Error;

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_current_span(false)
        .init();

    let cfg = AppConfig::from_env()?;
    let aws = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let store = Store::new(aws_sdk_dynamodb::Client::new(&aws), cfg.table_name.clone());

    // Production signs with a KMS keyring (non-extractable keys):
    // KMS_KEY_IDS is a comma-separated list, first = active signer, rest =
    // published-only (publish-before-sign rotation; runbook in
    // docs/deploy.md). KMS_KEY_ID remains as a single-key fallback. A PEM
    // fallback exists only for environments where KMS isn't wired.
    let keyring = std::env::var("KMS_KEY_IDS")
        .or_else(|_| std::env::var("KMS_KEY_ID"))
        .map(|ids| {
            ids.split(',')
                .map(str::trim)
                .filter(|id| !id.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        });
    let signer = match keyring {
        Ok(key_ids) if !key_ids.is_empty() => {
            Signer::Kms(KmsSigner::new(aws_sdk_kms::Client::new(&aws), key_ids).await?)
        }
        _ => match std::env::var("SIGNING_KEY_PEM") {
            Ok(pem) => Signer::Local(LocalSigner::from_pem(&pem)?),
            Err(_) => return Err("neither KMS_KEY_IDS nor SIGNING_KEY_PEM is set".into()),
        },
    };

    let state = AppState::new(cfg, store, signer)?;
    lambda_http::run(auth_service::build_router(state)).await
}
