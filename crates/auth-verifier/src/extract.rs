//! axum integration: an extractor that authenticates the request and an
//! `IntoResponse` implementation for [`VerifyError`].
//!
//! ```ignore
//! async fn handler(Authenticated(identity): Authenticated) -> String {
//!     identity.subject
//! }
//! let app = Router::new().route("/me", get(handler)).with_state(Arc::new(verifier));
//! ```

use crate::{Identity, RequestParts, Verifier, VerifyError};
use axum::extract::{FromRef, FromRequestParts, OriginalUri};
use axum::http::{HeaderValue, header, request::Parts};
use axum::response::{IntoResponse, Response};
use std::sync::Arc;

/// An authenticated caller.
#[derive(Debug, Clone)]
pub struct Authenticated(pub Identity);

impl<S> FromRequestParts<S> for Authenticated
where
    S: Send + Sync,
    Arc<Verifier>: FromRef<S>,
{
    type Rejection = VerifyError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let verifier = Arc::<Verifier>::from_ref(state);
        // Use the original URI so nested routers still compute the full path.
        let path = parts
            .extensions
            .get::<OriginalUri>()
            .map_or_else(|| parts.uri.path().to_owned(), |u| u.0.path().to_owned());
        let req = RequestParts::from_http(parts, &path)?;
        verifier.verify(&req).await.map(Authenticated)
    }
}

impl IntoResponse for VerifyError {
    fn into_response(self) -> Response {
        let mut resp = (self.status(), axum::Json(self.body())).into_response();
        let headers = resp.headers_mut();
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        if let Some(v) = self
            .www_authenticate()
            .and_then(|v| HeaderValue::from_str(&v).ok())
        {
            headers.insert(header::WWW_AUTHENTICATE, v);
        }
        if let Some(v) = self
            .dpop_nonce()
            .and_then(|v| HeaderValue::from_str(v).ok())
        {
            headers.insert("dpop-nonce", v);
        }
        resp
    }
}
