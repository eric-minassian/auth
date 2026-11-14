//! Shared application state.

use crate::clock::Clock;
use crate::config::Config;
use crate::kms::{self, KeyError, KmsSigner, NonceService, PublicKey};
use crate::store::Store;
use auth_core::crypto;
use auth_core::decide::{DPOP_MAX_IAT_SKEW_AUTH_SERVER, RpPolicy};
use auth_core::vtypes::VerifyKey;
use auth_verifier::{BoxFuture, DpopPolicy, PolicyError, Verifier, VerifierConfig};
use std::ops::Deref;
use std::sync::Arc;

/// How long a recorded DPoP `jti` is remembered (protocol §7.3). Covers the
/// whole window in which a proof can be accepted (`iat` skew and nonce windows).
pub const JTI_TTL: u64 = 600;

/// A startup error.
#[derive(Debug, thiserror::Error)]
pub enum InitError {
    /// A KMS key is missing or of the wrong type.
    #[error(transparent)]
    Key(#[from] KeyError),
    /// The account API verifier could not be configured.
    #[error("account API verifier: {0}")]
    Verifier(String),
}

/// Application state shared by all handlers.
#[derive(Debug, Clone)]
pub struct AppState(Arc<Inner>);

/// The contents of [`AppState`].
#[derive(Debug)]
pub struct Inner {
    /// Configuration.
    pub config: Config,
    /// WebAuthn policy.
    pub rp: RpPolicy,
    /// Storage.
    pub store: Store,
    /// Access-token signer.
    pub access_signer: KmsSigner,
    /// Refresh-token signer.
    pub refresh_signer: KmsSigner,
    /// Access-token public keys (active first), published in the JWKS.
    pub access_keys: Vec<PublicKey>,
    /// Refresh-token verification keys (active first).
    pub refresh_keys: Vec<VerifyKey>,
    /// DPoP nonces.
    pub nonces: NonceService,
    /// Verifier for the account API (audience = issuer).
    pub account_api: Verifier,
    /// Time source.
    pub clock: Arc<dyn Clock>,
}

impl Deref for AppState {
    type Target = Inner;

    fn deref(&self) -> &Inner {
        &self.0
    }
}

/// The account API's DPoP policy: nonces are required and every proof `jti`
/// is single-use (protocol §7.2, §7.3).
#[derive(Debug)]
struct ServicePolicy {
    nonces: NonceService,
    store: Store,
}

impl DpopPolicy for ServicePolicy {
    fn valid_nonces(&self, now: u64) -> BoxFuture<'_, Result<Option<Vec<Vec<u8>>>, PolicyError>> {
        Box::pin(async move {
            self.nonces
                .valid(now)
                .await
                .map(Some)
                .map_err(|e| PolicyError(e.to_string()))
        })
    }

    fn fresh_nonce(&self, now: u64) -> BoxFuture<'_, Result<Option<String>, PolicyError>> {
        Box::pin(async move {
            self.nonces
                .fresh(now)
                .await
                .map(Some)
                .map_err(|e| PolicyError(e.to_string()))
        })
    }

    fn record_jti<'a>(
        &'a self,
        jkt: &'a [u8],
        jti: &'a [u8],
        now: u64,
    ) -> BoxFuture<'a, Result<bool, PolicyError>> {
        Box::pin(async move {
            self.store
                .record_jti(jkt, jti, now, now.saturating_add(JTI_TTL))
                .await
                .map_err(|e| PolicyError(e.to_string()))
        })
    }
}

impl AppState {
    /// Builds the state, loading and validating every KMS key.
    pub async fn init(
        config: Config,
        kms_client: aws_sdk_kms::Client,
        dynamo_client: aws_sdk_dynamodb::Client,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, InitError> {
        let access_signer =
            KmsSigner::load(kms_client.clone(), config.access_token_key_id.clone()).await?;
        let refresh_signer =
            KmsSigner::load(kms_client.clone(), config.refresh_token_key_id.clone()).await?;
        let mut access_keys = vec![access_signer.public_key().clone()];
        access_keys.extend(
            kms::load_public_keys(&kms_client, &config.access_token_previous_key_ids).await?,
        );
        let mut refresh_keys = vec![refresh_signer.public_key().verify_key()];
        refresh_keys.extend(
            kms::load_public_keys(&kms_client, &config.refresh_token_previous_key_ids)
                .await?
                .iter()
                .map(PublicKey::verify_key),
        );
        kms::check_hmac_key(&kms_client, &config.dpop_nonce_key_id).await?;
        let nonces = NonceService::new(kms_client, config.dpop_nonce_key_id.clone());
        let store = Store::new(dynamo_client, config.table_name.clone());

        let mut vc = VerifierConfig::new(
            config.issuer.clone(),
            config.issuer.clone(),
            config.issuer.clone(),
        );
        vc.dpop_max_skew = DPOP_MAX_IAT_SKEW_AUTH_SERVER;
        vc.allow_insecure_localhost = config.local_mode;
        let account_api =
            Verifier::with_static_keys(vc, access_keys.iter().map(PublicKey::verify_key).collect())
                .map_err(|e| InitError::Verifier(e.to_string()))?
                .with_policy(Arc::new(ServicePolicy {
                    nonces: nonces.clone(),
                    store: store.clone(),
                }));

        let rp = RpPolicy {
            rp_id_hash: crypto::sha256(config.rp_id.as_bytes()).to_vec(),
            origins: config
                .allowed_origins
                .iter()
                .map(|o| o.as_bytes().to_vec())
                .collect(),
        };
        Ok(Self(Arc::new(Inner {
            config,
            rp,
            store,
            access_signer,
            refresh_signer,
            access_keys,
            refresh_keys,
            nonces,
            account_api,
            clock,
        })))
    }
}
