//! DPoP at the token-style endpoints (`/v1/token`, `/v1/*/verify`), where the
//! proof has no access token: protocol §7, RFC 9449 §5 and §8.

use crate::error::ApiError;
use crate::state::{AppState, JTI_TTL};
use auth_core::decide::{self, DPOP_MAX_IAT_SKEW_AUTH_SERVER, DpopExpect, DpopOk, Reject};
use axum::http::HeaderMap;

/// Checks the request's DPoP proof (nonce required, `jti` single-use) and
/// returns the proof key's thumbprint.
pub async fn require_proof(
    state: &AppState,
    headers: &HeaderMap,
    method: &str,
    path: &str,
    now: u64,
) -> Result<DpopOk, ApiError> {
    let mut values = headers.get_all("dpop").iter();
    let proof = match (values.next(), values.next()) {
        (Some(v), None) => v
            .to_str()
            .map_err(|_| ApiError::InvalidDpopProof("non-ASCII header".into()))?,
        (None, _) => return Err(ApiError::InvalidDpopProof("missing".into())),
        (Some(_), Some(_)) => {
            return Err(ApiError::InvalidDpopProof(
                "more than one DPoP header".into(),
            ));
        }
    };
    let expect = DpopExpect {
        htm: method.as_bytes().to_vec(),
        htu: format!("{}{path}", state.config.issuer).into_bytes(),
        now,
        max_skew: DPOP_MAX_IAT_SKEW_AUTH_SERVER,
        valid_nonces: Some(state.nonces.valid(now).await?),
        access_token: None,
    };
    let ok = match decide::check_dpop(proof.as_bytes(), &expect) {
        Ok(ok) => ok,
        Err(Reject::DpopNonceMissing | Reject::DpopNonceInvalid) => {
            return Err(ApiError::UseDpopNonce);
        }
        Err(r) => return Err(ApiError::InvalidDpopProof(format!("{r:?}"))),
    };
    if !state
        .store
        .record_jti(&ok.jkt, &ok.jti, now, now.saturating_add(JTI_TTL))
        .await?
    {
        return Err(ApiError::InvalidDpopProof("replayed".into()));
    }
    Ok(ok)
}
