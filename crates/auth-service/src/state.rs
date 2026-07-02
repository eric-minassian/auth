use std::sync::Arc;

use tokio::sync::OnceCell;
use webauthn_rs::prelude::WebauthnError;
use webauthn_rs::{Webauthn, WebauthnBuilder};

use crate::config::AppConfig;
use crate::jwt::Signer;
use crate::store::{Store, StoreError};

#[derive(Clone)]
pub struct AppState {
    pub cfg: Arc<AppConfig>,
    pub store: Store,
    pub signer: Arc<Signer>,
    pub webauthn: Arc<Webauthn>,
    /// HTTP client for back-channel logout dispatch (short timeout,
    /// best-effort).
    pub http: reqwest::Client,
    /// Server-wide DPoP nonce key (RFC 9449 §8), fetched from the store once
    /// per process and cached — nonces are derived, never stored.
    dpop_nonce_key: Arc<OnceCell<[u8; 32]>>,
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
            dpop_nonce_key: Arc::new(OnceCell::new()),
        })
    }

    /// The shared DPoP nonce key, loaded (or created) on first use.
    pub async fn dpop_nonce_key(&self) -> Result<[u8; 32], StoreError> {
        self.dpop_nonce_key
            .get_or_try_init(|| self.store.get_or_create_dpop_nonce_key())
            .await
            .copied()
    }
}
