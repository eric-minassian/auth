use std::sync::Arc;

use webauthn_rs::prelude::WebauthnError;
use webauthn_rs::{Webauthn, WebauthnBuilder};

use crate::config::AppConfig;
use crate::jwt::Signer;
use crate::store::Store;

#[derive(Clone)]
pub struct AppState {
    pub cfg: Arc<AppConfig>,
    pub store: Store,
    pub signer: Arc<Signer>,
    pub webauthn: Arc<Webauthn>,
    /// HTTP client for back-channel logout dispatch (short timeout,
    /// best-effort).
    pub http: reqwest::Client,
}

impl AppState {
    pub fn new(cfg: AppConfig, store: Store, signer: Signer) -> Result<Self, WebauthnError> {
        let webauthn = WebauthnBuilder::new(&cfg.rp_id, &cfg.rp_origin)?
            .rp_name("ericminassian.com")
            .build()?;
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(3))
            .build()
            .unwrap_or_default();
        Ok(Self {
            cfg: Arc::new(cfg),
            store,
            signer: Arc::new(signer),
            webauthn: Arc::new(webauthn),
            http,
        })
    }
}
