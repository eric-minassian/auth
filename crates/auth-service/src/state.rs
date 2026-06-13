use std::sync::Arc;

use webauthn_rs::prelude::WebauthnError;
use webauthn_rs::{Webauthn, WebauthnBuilder};

use crate::config::AppConfig;
use crate::email::Mailer;
use crate::jwt::Signer;
use crate::store::Store;

#[derive(Clone)]
pub struct AppState {
    pub cfg: Arc<AppConfig>,
    pub store: Store,
    pub signer: Arc<Signer>,
    pub webauthn: Arc<Webauthn>,
    pub mailer: Arc<Mailer>,
}

impl AppState {
    pub fn new(
        cfg: AppConfig,
        store: Store,
        signer: Signer,
        mailer: Mailer,
    ) -> Result<Self, WebauthnError> {
        let webauthn = WebauthnBuilder::new(&cfg.rp_id, &cfg.rp_origin)?
            .rp_name("ericminassian.com")
            .build()?;
        Ok(Self {
            cfg: Arc::new(cfg),
            store,
            signer: Arc::new(signer),
            webauthn: Arc::new(webauthn),
            mailer: Arc::new(mailer),
        })
    }
}
