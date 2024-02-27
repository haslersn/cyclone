use leptos::*;
use leptos_router::*;
use serde::{Deserialize, Serialize};

use crate::error::{CycloneError, ErrorTemplate};
use crate::html::get_html_resource;

#[cfg(feature = "ssr")]
use {
    crate::{fileserv::CycloneState, hydra::map_get_login_request_error, ldap::get_claims},
    ory_hydra_client::{
        apis::o_auth2_api::{
            accept_o_auth2_login_request, get_o_auth2_login_request, reject_o_auth2_login_request,
        },
        models::{AcceptOAuth2LoginRequest, RejectOAuth2Request},
    },
    serde_json::Value,
};

#[derive(Clone, Params, PartialEq, Serialize, Deserialize, Debug)]
struct LoginQuery {
    login_challenge: String,
}

// Client-side info about a consent request
#[derive(Clone, Serialize, Deserialize)]
pub struct LoginRequestCSI {
    challenge: String,
}

#[component]
pub fn Login() -> impl IntoView {
    let handle_login = create_server_action::<HandleLogin>();
    let handle_login_value = handle_login.value();

    let login_request = create_blocking_resource(
        || use_query::<LoginQuery>().get().ok(),
        |query| async {
            if let Some(query) = query {
                get_login_request(query.login_challenge).await
            } else {
                Err(CycloneError::LoginChallengeMissing.into())
            }
        },
    );

    let brand = get_html_resource("brand");

    view! {
        <Suspense fallback=|| { "Loading ..." }>
            <ErrorTemplate errors=Signal::derive(move || {
                let mut errors = Errors::default();
                if let Some(Err(e)) = handle_login_value.get() {
                    errors.insert("handle_login".into(), e);
                }
                if let Some(Err(e)) = login_request.get() {
                    errors.insert("get_login_request".into(), e);
                }
                errors
            })/>

            {move || {
                let brand = brand.get();
                let Some(Ok(login_request)) = login_request.get() else {
                    return ().into_view();
                };
                let challenge = login_request.challenge;
                view! {
                    <div class="greeting">"Sign into your " {brand} " account"</div>

                    <ActionForm class="login-form" action=handle_login>
                        <input type="text" name="username" placeholder="Username"/>
                        <input type="password" name="password" placeholder="Password"/>
                        <label for="remember" class="checkbox">
                            <input type="checkbox" name="remember" value="true" id="remember"/>
                            "Remember me"
                        </label>
                        <input type="hidden" name="login_challenge" value=challenge/>
                        // TODO: CSRF-token
                        <button type="submit" name="accept" value="true" class="prefer">
                            "Login"
                        </button>
                        <button type="submit" name="accept" value="false">
                            "Cancel"
                        </button>
                    </ActionForm>
                }
                    .into_view()
            }}

        </Suspense>
    }
}

#[server(GetLoginRequest)]
async fn get_login_request(
    login_challenge: String,
) -> Result<LoginRequestCSI, ServerFnError<CycloneError>> {
    let state = expect_context::<CycloneState>();
    let hydra_config = state.hydra_config();
    let login_request = get_o_auth2_login_request(&hydra_config, &login_challenge)
        .await
        .map_err(map_get_login_request_error)?;
    if login_request.skip {
        accept_login(
            &login_request.challenge,
            login_request.subject.clone(),
            false,
        )
        .await?;
    }
    Ok(LoginRequestCSI {
        challenge: login_request.challenge,
    })
}

#[server(HandleLogin)]
async fn handle_login(
    login_challenge: String,
    username: String,
    password: String,
    remember: Option<String>,
    accept: String,
) -> Result<(), ServerFnError<CycloneError>> {
    if accept != "true" {
        return reject_login(&login_challenge).await;
    }

    let remember = remember.as_deref() == Some("true");

    match authenticate(&username, &password).await {
        Ok(Some(subject)) => {
            // Login successful
            accept_login(&login_challenge, subject, remember).await
        }
        Ok(None) => {
            // Invalid credentials
            Err(CycloneError::InvalidCredentials.into())
        }
        Err(e) => {
            // Server error
            Err(e.into())
        }
    }
}

#[cfg(feature = "ssr")]
async fn authenticate(username: &str, password: &str) -> Result<Option<String>, CycloneError> {
    let Some(sub) = get_claims(username, &["sub"], Some(password))
        .await?
        .get("sub")
        .map(Clone::clone)
    else {
        return Ok(None);
    };

    let Value::String(sub) = sub else {
        logging::error!("Error: sub claim must be scalar (use `first` instead of `all`)");
        return Err(CycloneError::InternalServerError);
    };

    Ok(Some(sub))
}

#[cfg(feature = "ssr")]
async fn accept_login(
    login_challenge: &str,
    subject: String,
    remember: bool,
) -> Result<(), ServerFnError<CycloneError>> {
    let mut body = AcceptOAuth2LoginRequest::new(subject);
    body.remember = Some(remember);
    body.remember_for = Some(86400);

    let state = expect_context::<CycloneState>();
    let hydra_config = state.hydra_config();

    match accept_o_auth2_login_request(&hydra_config, login_challenge, Some(&body)).await {
        Ok(r) => {
            leptos_axum::redirect(&r.redirect_to);
            Ok(())
        }
        Err(e) => {
            logging::error!("Error: failed to accept login request: {e}");
            Err(CycloneError::InternalServerError.into())
        }
    }
}

#[cfg(feature = "ssr")]
async fn reject_login(login_challenge: &str) -> Result<(), ServerFnError<CycloneError>> {
    let mut body = RejectOAuth2Request::new();
    body.error_description = Some("login has been cancelled".to_string());

    let state = expect_context::<CycloneState>();
    let hydra_config = state.hydra_config();

    match reject_o_auth2_login_request(&hydra_config, login_challenge, Some(&body)).await {
        Ok(r) => {
            leptos_axum::redirect(&r.redirect_to);
            Ok(())
        }
        Err(e) => {
            logging::error!("Error: failed to reject login request: {e}");
            Err(CycloneError::InternalServerError.into())
        }
    }
}
