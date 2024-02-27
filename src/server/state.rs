use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::FromRef;
use leptos::*;
use leptos_axum::extract;
use ory_hydra_client::apis::configuration::Configuration;
use tokio::sync::Mutex;
use tower_sessions::session::Id;
use tower_sessions::Session;

use crate::config::CycloneConfig;
use crate::error::CycloneError;

#[derive(Clone)]
pub struct CycloneState(Arc<InnerState>);

impl CycloneState {
    pub fn new(leptos_options: LeptosOptions, cyclone_config: CycloneConfig) -> Self {
        let hydra_config = (&cyclone_config.hydra).into();
        Self(Arc::new(InnerState {
            leptos_options,
            cyclone_config,
            hydra_config,
            bound_sessions: Default::default(),
        }))
    }

    pub fn leptos_options(&self) -> &LeptosOptions {
        &self.0.leptos_options
    }

    pub fn cyclone_config(&self) -> &CycloneConfig {
        &self.0.cyclone_config
    }

    pub fn hydra_config(&self) -> &Configuration {
        &self.0.hydra_config
    }

    pub fn bound_sessions(&self) -> &Mutex<HashMap<String, Id>> {
        &self.0.bound_sessions
    }
}

struct InnerState {
    leptos_options: LeptosOptions,
    cyclone_config: CycloneConfig,
    hydra_config: Configuration,
    bound_sessions: Mutex<HashMap<String, Id>>,
}

impl FromRef<CycloneState> for LeptosOptions {
    fn from_ref(state: &CycloneState) -> Self {
        state.0.leptos_options.clone()
    }
}

pub async fn extract_session() -> Result<Session, CycloneError> {
    extract().await.map_err(|e| {
        leptos::logging::error!("Error: failed to extract session: {e}");
        CycloneError::InternalServerError
    })
}

pub async fn bind_session(key: String) -> Result<(), CycloneError> {
    let state = expect_context::<CycloneState>();
    let mut bound_sessions = state.bound_sessions().lock().await;
    let session = extract_session().await?;

    if let Some(&sid) = bound_sessions.get(&key) {
        if session.id() != Some(sid) {
            // The key was already bound to a different user.
            return Err(CycloneError::SessionExpired);
        }
    } else {
        let sid = if let Some(sid) = session.id() {
            sid
        } else {
            session.save().await.map_err(|e| {
                leptos::logging::error!("Error: failed to save session: {e}");
                CycloneError::InternalServerError
            })?;
            // Saving the session generates a session ID.
            // Therefore it's no longer none, so we can unwrap.
            session.id().unwrap()
        };
        bound_sessions.insert(key, sid);
    }
    Ok(())
}

pub async fn verify_session(key: &str) -> Result<(), CycloneError> {
    let state = expect_context::<CycloneState>();
    let bound_sessions = state.bound_sessions().lock().await;
    let session = extract_session().await?;

    if session.id().as_ref() != bound_sessions.get(key) {
        // The key was already bound to a different user.
        Err(CycloneError::SessionExpired)
    } else {
        Ok(())
    }
}
