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

    // Production signs with KMS (non-extractable key). A PEM fallback exists
    // only for environments where KMS isn't wired (e.g. an ad-hoc test stage).
    let signer = match std::env::var("KMS_KEY_ID") {
        Ok(key_id) => Signer::Kms(KmsSigner::new(aws_sdk_kms::Client::new(&aws), key_id).await?),
        Err(_) => match std::env::var("SIGNING_KEY_PEM") {
            Ok(pem) => Signer::Local(LocalSigner::from_pem(&pem)?),
            Err(_) => return Err("neither KMS_KEY_ID nor SIGNING_KEY_PEM is set".into()),
        },
    };

    let state = AppState::new(cfg, store, signer)?;
    lambda_http::run(auth_service::build_router(state)).await
}
