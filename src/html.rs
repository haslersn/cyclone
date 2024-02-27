use leptos::*;

use crate::error::CycloneError;

#[cfg(feature = "ssr")]
use crate::server::state::CycloneState;

#[server(GetHtml)]
async fn get_html(key: String) -> Result<String, ServerFnError<CycloneError>> {
    let state = expect_context::<CycloneState>();
    let html_config = &state.cyclone_config().html;
    match key.as_str() {
        "title" => Ok(html_config.title.clone()),
        "header" => Ok(html_config.header.clone()),
        "footer" => Ok(html_config.footer.clone()),
        "brand" => Ok(html_config.brand.clone()),
        _ => Err(CycloneError::NotFound.into()),
    }
}

pub fn get_html_resource(key: &str) -> Resource<(), String> {
    let key = key.to_string();
    create_blocking_resource(
        || (),
        move |_| {
            let key = key.clone();
            async { get_html(key).await.unwrap_or_default() }
        },
    )
}
