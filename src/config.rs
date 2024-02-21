use std::collections::HashMap;
use std::net::SocketAddr;

use leptos::leptos_config::{Env, ReloadWSProtocol};
use leptos::LeptosOptions;
use serde::Deserialize;

use crate::hydra::HydraConfig;
use crate::ldap::LdapConfig;

#[derive(Clone, Debug, Deserialize)]
pub struct CycloneConfig {
    pub html: HtmlConfig,
    pub hydra: HydraConfig,
    pub leptos: Option<LeptosConfig>,
    pub ldap: LdapConfig,
    pub scopes: HashMap<String, ScopeConfig>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct HtmlConfig {
    pub title: String,
    pub header: String,
    pub footer: String,
    pub brand: String,
}

#[derive(Clone, Debug, Deserialize, Default)]
pub struct LeptosConfig {
    site_root: Option<String>,
    env: Option<Env>,
    site_addr: Option<SocketAddr>,
    reload_port: Option<u32>,
    reload_external_port: Option<u32>,
    reload_ws_protocol: Option<ReloadWSProtocol>,
    not_found_path: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ScopeConfig {
    /// Display name shown to users. If None, the scope does not get listed in the UI.
    pub display: Option<String>,
    pub claims: Vec<String>,
}

pub fn mutate_leptos_options(
    mut leptos_options: LeptosOptions,
    config: Option<&LeptosConfig>,
) -> LeptosOptions {
    let Some(config) = config else {
        return leptos_options;
    };
    if let Some(site_root) = &config.site_root {
        leptos_options.site_root = site_root.clone();
    }
    if let Some(env) = &config.env {
        leptos_options.env = env.clone();
    }
    if let Some(site_addr) = &config.site_addr {
        leptos_options.site_addr = site_addr.clone();
    }
    if let Some(reload_port) = &config.reload_port {
        leptos_options.reload_port = *reload_port;
    }
    if let Some(_) = &config.reload_external_port {
        leptos_options.reload_external_port = config.reload_external_port;
    }
    if let Some(reload_ws_protocol) = &config.reload_ws_protocol {
        leptos_options.reload_ws_protocol = reload_ws_protocol.clone();
    }
    if let Some(not_found_path) = &config.not_found_path {
        leptos_options.not_found_path = not_found_path.clone();
    }

    leptos_options
}
