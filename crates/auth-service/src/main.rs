//! Entry point: runs on AWS Lambda when `AWS_LAMBDA_RUNTIME_API` is set and as
//! a local HTTP server otherwise.

use auth_service::clock::SystemClock;
use auth_service::config::Config;
use auth_service::{AppState, router};
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    // The AWS SDK logs credential details at INFO; keep it at WARN whatever the
    // base level is.
    let mut filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    for directive in [
        "aws_config=warn",
        "aws_smithy_runtime=warn",
        "aws_sdk_dynamodb=warn",
        "aws_sdk_kms=warn",
    ] {
        filter = filter.add_directive(directive.parse()?);
    }
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(filter)
        .with_current_span(true)
        .with_target(false)
        .without_time() // CloudWatch timestamps every line
        .init();

    let config = Config::from_env()?;
    let sdk = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let state = AppState::init(
        config.clone(),
        aws_sdk_kms::Client::new(&sdk),
        aws_sdk_dynamodb::Client::new(&sdk),
        Arc::new(SystemClock),
    )
    .await?;
    let app = router(state);

    if config.local_mode {
        let listener = tokio::net::TcpListener::bind(config.listen_addr).await?;
        tracing::info!(addr = %config.listen_addr, issuer = %config.issuer, "listening (local mode)");
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = tokio::signal::ctrl_c().await;
            })
            .await?;
    } else {
        lambda_http::run(app).await?;
    }
    Ok(())
}
