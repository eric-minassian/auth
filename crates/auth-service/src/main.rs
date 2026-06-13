use auth_service::config::AppConfig;
use auth_service::email::{Mailer, SesMailer};
use auth_service::jwt::{LocalSigner, Signer};
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

    // KMS signer lands with the infra milestone; until then a PEM key from the
    // environment (e.g. an SSM-injected secret) keeps deployed testing honest.
    let signer = match std::env::var("SIGNING_KEY_PEM") {
        Ok(pem) => Signer::Local(LocalSigner::from_pem(&pem)?),
        Err(_) => return Err("SIGNING_KEY_PEM not set (KMS signer not implemented yet)".into()),
    };

    let from_address = std::env::var("EMAIL_FROM").map_err(|_| "EMAIL_FROM not set")?;
    let mailer = Mailer::Ses(SesMailer::new(
        aws_sdk_sesv2::Client::new(&aws),
        from_address,
    ));

    let state = AppState::new(cfg, store, signer, mailer)?;
    lambda_http::run(auth_service::build_router(state)).await
}
