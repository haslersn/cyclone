pub mod components;
#[cfg(feature = "ssr")]
pub mod config;
pub mod error;
#[cfg(feature = "ssr")]
pub mod fileserv;
pub mod html;
#[cfg(feature = "ssr")]
pub mod hydra;
#[cfg(feature = "ssr")]
pub mod ldap;

#[cfg(feature = "hydrate")]
#[wasm_bindgen::prelude::wasm_bindgen]
pub fn hydrate() {
    console_error_panic_hook::set_once();
    leptos::mount_to_body(crate::components::app::App);
}
