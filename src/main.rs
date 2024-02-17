use std::process::ExitCode;

use axum::Router;
use config::{Config, ConfigError, Environment, File};
use cyclone::components::app::App;
use cyclone::config::{mutate_leptos_options, CycloneConfig};
use cyclone::fileserv::{file_and_error_handler, CycloneState};
use leptos::*;
use leptos_axum::{generate_route_list, LeptosRoutes};
use leptos_config::errors::LeptosConfigError;
use thiserror::Error;

#[derive(Debug, Error)]
enum Exit {
    #[error("Error reading configuration: {0}")]
    ErrorReadingConfig(ConfigError),
    #[error("Invalid configuration: {0}")]
    InvalidConfig(ConfigError),
    #[error("Leptos configuration error: {0}")]
    LeptosConfigError(LeptosConfigError),
}

#[tokio::main]
async fn main() -> ExitCode {
    env_logger::init();

    if let Err(e) = serve().await {
        logging::error!("{e}");
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

async fn serve() -> Result<(), Exit> {
    let cyclone_config: CycloneConfig = Config::builder()
        .add_source(File::with_name("config").required(false))
        .add_source(Environment::with_prefix("cyclone").separator("__"))
        .build()
        .map_err(Exit::ErrorReadingConfig)?
        .try_deserialize()
        .map_err(Exit::InvalidConfig)?;

    // Setting get_configuration(None) means we'll be using cargo-leptos's env values
    // For deployment these variables are:
    // <https://github.com/leptos-rs/start-axum#executing-a-server-on-a-remote-machine-without-the-toolchain>
    // Alternately a file can be specified such as Some("Cargo.toml")
    // The file would need to be included with the executable when moved to deployment
    let leptos_options = {
        let leptos_config = get_configuration(None)
            .await
            .map_err(Exit::LeptosConfigError)?;
        mutate_leptos_options(leptos_config.leptos_options, cyclone_config.leptos.as_ref())
    };

    let addr = leptos_options.site_addr;
    let routes = generate_route_list(App);

    let state = CycloneState::new(leptos_options, cyclone_config);

    // build our application with a route
    let app = Router::new()
        .leptos_routes(&state, routes, App)
        .fallback(file_and_error_handler)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    logging::log!("listening on http://{}", &addr);
    axum::serve(listener, app.into_make_service())
        .await
        .unwrap();
    Ok(())
}
