use leptos::*;

use crate::error::CycloneError;

#[cfg(feature = "ssr")]
use {
    crate::server::state::extract_session,
    rand::{distributions::Alphanumeric, Rng},
};

#[server(GetCsrfToken)]
async fn get_csrf_token() -> Result<String, ServerFnError<CycloneError>> {
    let session = extract_session().await?;

    let opt_token = session.get("csrf_token").await.map_err(|e| {
        leptos::logging::error!("Error: failed to get csrf_token from session: {e}");
        CycloneError::InternalServerError
    })?;

    let token = if let Some(token) = opt_token {
        token
    } else {
        let token: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(43)
            .map(char::from)
            .collect();
        session
            .insert("csrf_token", token.clone())
            .await
            .map_err(|e| {
                leptos::logging::error!("Error: failed to insert csrf_token into session: {e}");
                CycloneError::InternalServerError
            })?;
        token
    };

    // TODO: protect against BREACH attack

    Ok(token)
}

pub fn get_csrf_token_resource() -> Resource<(), String> {
    create_blocking_resource(
        || (),
        move |_| async { get_csrf_token().await.unwrap_or_default() },
    )
}

#[cfg(feature = "ssr")]
pub async fn verify_csrf_token(token: &str) -> Result<(), CycloneError> {
    let session = extract_session().await?;

    let expected_token: Option<String> = session.get("csrf_token").await.map_err(|e| {
        leptos::logging::error!("Error: failed to get csrf_token from session: {e}");
        CycloneError::InternalServerError
    })?;

    if expected_token.as_deref() == Some(token) {
        Ok(())
    } else {
        Err(CycloneError::SessionExpired)
    }
}
