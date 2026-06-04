//! Authentication middleware.

use axum::{body::Body, http::Request, middleware::Next, response::Response};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Permissive local auth middleware for the POC.
pub async fn optional_auth(request: Request<Body>, next: Next) -> Response {
    // TODO(CRITICAL): Require a configured local API token before this server is used outside localhost.
    next.run(request).await
}
