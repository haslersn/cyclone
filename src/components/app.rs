use crate::components::consent::Consent;
use crate::components::login::Login;
use crate::error::{CycloneError, ErrorTemplate};
use crate::html::get_html_resource;
use leptos::*;
use leptos_meta::*;
use leptos_router::*;

#[component]
pub fn App() -> impl IntoView {
    // Provides context that manages stylesheets, titles, meta tags, etc.
    provide_meta_context();

    let title = get_html_resource("title");

    view! {
        <Stylesheet id="leptos" href="/pkg/cyclone.css"/>

        <Suspense>
            <Title text=move || title.get().unwrap_or_default()/>
        </Suspense>

        <main>
            <Router fallback=|| view! { <NotFound/> }>
                <Routes>
                    <Route path="/auth" view=ContentBox>
                        <Route path="/login" view=Login ssr=SsrMode::PartiallyBlocked/>
                        <Route path="/consent" view=Consent ssr=SsrMode::PartiallyBlocked/>
                    </Route>
                </Routes>
            </Router>
        </main>
    }
}

#[component]
fn ContentBox() -> impl IntoView {
    let header = get_html_resource("header");
    let footer = get_html_resource("footer");
    view! {
        <Suspense>
            <div class="content-box">
                <div class="header" inner_html=move || header.get().unwrap_or_default()></div>

                // This gets replaced by view of the matched nested route
                <Outlet/>
            </div>

            <div class="footer" inner_html=move || footer.get().unwrap_or_default()></div>
        </Suspense>
    }
}

#[component]
fn NotFound() -> impl IntoView {
    #[cfg(feature = "ssr")]
    {
        if let Some(response) = use_context::<leptos_axum::ResponseOptions>() {
            response.set_status(http::StatusCode::NOT_FOUND);
        }
    }

    let mut errors = Errors::default();
    errors.insert_with_default_key(CycloneError::NotFound);
    view! { <ErrorTemplate errors=create_rw_signal(errors).into()/> }
}
