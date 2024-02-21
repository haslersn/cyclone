use std::sync::Arc;

use axum::body::Body;
use axum::extract::{FromRef, State};
use axum::http::{Request, Response, StatusCode, Uri};
use axum::response::{IntoResponse, Response as AxumResponse};
use leptos::*;
use ory_hydra_client::apis::configuration::Configuration;
use tower::ServiceExt;
use tower_http::services::ServeDir;

use crate::components::app::App;
use crate::config::CycloneConfig;

#[derive(Clone)]
pub struct CycloneState(Arc<InnerState>);

impl CycloneState {
    pub fn new(leptos_options: LeptosOptions, cyclone_config: CycloneConfig) -> Self {
        let hydra_config = (&cyclone_config.hydra).into();
        Self(Arc::new(InnerState {
            leptos_options,
            cyclone_config,
            hydra_config,
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
}

#[derive(Clone)]
struct InnerState {
    leptos_options: LeptosOptions,
    cyclone_config: CycloneConfig,
    hydra_config: Configuration,
}

impl FromRef<CycloneState> for LeptosOptions {
    fn from_ref(state: &CycloneState) -> Self {
        state.0.leptos_options.clone()
    }
}

pub async fn file_and_error_handler(
    uri: Uri,
    State(state): State<CycloneState>,
    req: Request<Body>,
) -> AxumResponse {
    let leptos_options = state.leptos_options().clone();
    let root = &leptos_options.site_root;
    let res = get_static_file(uri.clone(), root).await.unwrap();
    if res.status() == StatusCode::OK {
        res.into_response()
    } else {
        let context = move || provide_context(state.clone());
        let handler = leptos_axum::render_app_to_stream_with_context(leptos_options, context, App);
        handler(req).await.into_response()
    }
}

async fn get_static_file(uri: Uri, root: &str) -> Result<Response<Body>, (StatusCode, String)> {
    let req = Request::builder()
        .uri(uri.clone())
        .body(Body::empty())
        .unwrap();
    // `ServeDir` implements `tower::Service` so we can call it with `tower::ServiceExt::oneshot`
    // This path is relative to the cargo root
    match ServeDir::new(root).oneshot(req).await {
        Ok(res) => Ok(res.into_response()),
        Err(err) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Something went wrong: {err}"),
        )),
    }
}
