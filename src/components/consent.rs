use leptos::*;
use leptos_router::*;
use serde::{Deserialize, Serialize};

use crate::error::{CycloneError, ErrorTemplate};
use crate::html::get_html_resource;

#[cfg(feature = "ssr")]
use {
    crate::{
        fileserv::CycloneState, hydra::map_get_consent_request_error, ldap::get_claims_for_scopes,
    },
    ory_hydra_client::{
        apis::{
            o_auth2_api::get_o_auth2_consent_request,
            o_auth2_api::{accept_o_auth2_consent_request, reject_o_auth2_consent_request},
        },
        models::{
            AcceptOAuth2ConsentRequest, AcceptOAuth2ConsentRequestSession, OAuth2ConsentRequest,
            RejectOAuth2Request,
        },
    },
};

#[derive(Clone, Debug, Params, PartialEq, Serialize, Deserialize)]
struct ConsentQuery {
    consent_challenge: String,
}

// Client-side info about a consent request
#[derive(Clone, Serialize, Deserialize)]
pub struct ConsentRequestCSI {
    challenge: String,
    client_name: Option<String>,
    scope_display_names: Vec<String>,
}

#[component]
pub fn Consent() -> impl IntoView {
    let errors = create_rw_signal(Errors::default());

    let consent_request = create_blocking_resource(
        || use_query::<ConsentQuery>().get().ok(),
        |query| async {
            if let Some(query) = query {
                get_consent_request(query.consent_challenge).await
            } else {
                Err(CycloneError::ConsentChallengeMissing)?
            }
        },
    );
    create_effect({
        move |_| {
            errors.update(|errors| {
                if let Some(Err(e)) = consent_request.get() {
                    errors.insert("get_consent_request".into(), e);
                } else {
                    errors.remove(&"get_consent_request".into());
                }
            });
        }
    });

    let handle_consent = create_server_action::<HandleConsent>();
    let handle_consent_value = handle_consent.value();
    create_effect(move |_| {
        errors.update(|errors| {
            if let Some(Err(e)) = handle_consent_value.get() {
                errors.insert("handle_consent".into(), e);
            } else {
                errors.remove(&"handle_consent".into());
            }
        });
    });

    let brand = get_html_resource("brand");

    view! {
        <ErrorTemplate errors=errors.into()/>

        <Suspense fallback=|| {
            "Loading ..."
        }>

            {move || {
                let brand = brand.get();
                let Some(Ok(consent_request)) = consent_request.get() else {
                    return ().into_view();
                };
                let challenge1 = consent_request.challenge.clone();
                let challenge2 = consent_request.challenge;
                let client_name = consent_request.client_name;
                let scopes_view = consent_request
                    .scope_display_names
                    .iter()
                    .map(|display| view! { <li>Your <b>{display}</b></li> })
                    .collect_view();
                view! {
                    <div class="greeting">
                        <span class="appname">
                            {client_name.unwrap_or("An application".to_string())}
                        </span>
                        " wants to access your "
                        {brand}
                        " account"
                    </div>

                    "This will allow it to access the following information:"
                    <ul>{scopes_view}</ul>

                    <ActionForm class="consent-form" action=handle_consent>
                        <input type="hidden" name="consent_challenge" value=challenge1/>
                        <input type="hidden" name="accept" value="true"/>
                        <button type="submit" class="prefer">
                            "Accept"
                        </button>
                    </ActionForm>
                    <ActionForm class="consent-form" action=handle_consent>
                        <input type="hidden" name="consent_challenge" value=challenge2/>
                        <button type="submit">"Reject"</button>
                    </ActionForm>
                }
                    .into_view()
            }}

        </Suspense>
    }
}

#[server(GetConsentRequest)]
async fn get_consent_request(
    consent_challenge: String,
) -> Result<ConsentRequestCSI, ServerFnError<CycloneError>> {
    let state = expect_context::<CycloneState>();
    let hydra_config = state.hydra_config();
    let consent_request = get_o_auth2_consent_request(hydra_config, &consent_challenge)
        .await
        .map_err(map_get_consent_request_error)?;
    if consent_request.skip == Some(true) {
        accept_consent(&consent_request).await?;
    }
    let Some(requested_scope) = consent_request.requested_scope else {
        logging::error!("Error: consent request has no requested_scope");
        return Err(CycloneError::InternalServerError.into());
    };

    let client_name = consent_request
        .client
        .unwrap()
        .client_name
        .and_then(|name| if name == "" { None } else { Some(name) });

    let scope_display_names = {
        let state = expect_context::<CycloneState>();
        let scopes_config = &state.cyclone_config().scopes;
        requested_scope
            .iter()
            .filter_map(|s| {
                if let Some(scope_config) = scopes_config.get(s) {
                    scope_config.display.clone()
                } else {
                    logging::warn!(
                "Warning: requested scope {s} does not exist (i.e., is missing from configuration)"
            );
                    None
                }
            })
            .collect()
    };

    Ok(ConsentRequestCSI {
        challenge: consent_request.challenge,
        client_name,
        scope_display_names,
    })
}

#[server(HandleConsent)]
async fn handle_consent(
    consent_challenge: String,
    accept: Option<String>,
) -> Result<(), ServerFnError<CycloneError>> {
    if accept.as_deref() == Some("true") {
        let state = expect_context::<CycloneState>();
        let hydra_config = state.hydra_config();
        let consent_request = get_o_auth2_consent_request(&hydra_config, &consent_challenge)
            .await
            .map_err(map_get_consent_request_error)?;
        accept_consent(&consent_request).await
    } else {
        reject_consent(&consent_challenge).await
    }
}

#[cfg(feature = "ssr")]
async fn accept_consent(
    consent_request: &OAuth2ConsentRequest,
) -> Result<(), ServerFnError<CycloneError>> {
    let Some(subject) = &consent_request.subject else {
        logging::error!("Error: consent request has no subject");
        return Err(CycloneError::InternalServerError.into());
    };
    let Some(scope) = &consent_request.requested_scope else {
        logging::error!("Error: consent request has no requested_scope");
        return Err(CycloneError::InternalServerError.into());
    };

    // `check_password = None`, because the user is already logged in.
    let claims = get_claims_for_scopes(subject, scope, None).await?;

    let mut session = AcceptOAuth2ConsentRequestSession::new();
    session.id_token = Some(serde_json::json!(claims));

    let mut body = AcceptOAuth2ConsentRequest::new();
    body.grant_scope = Some(scope.clone());
    // TODO: audience?
    // Reuse consent if the same client asks the same user for the same, or a subset of, scope.
    body.remember = Some(true);
    body.session = Some(Box::new(session));

    let state = expect_context::<CycloneState>();
    let hydra_config = state.hydra_config();

    match accept_o_auth2_consent_request(&hydra_config, &consent_request.challenge, Some(&body))
        .await
    {
        Ok(r) => {
            leptos_axum::redirect(&r.redirect_to);
            Ok(())
        }
        Err(e) => {
            logging::error!("Error: failed to accept consent request: {e}");
            Err(CycloneError::InternalServerError)?
        }
    }
}

#[cfg(feature = "ssr")]
async fn reject_consent(consent_challenge: &str) -> Result<(), ServerFnError<CycloneError>> {
    let mut body = RejectOAuth2Request::new();
    body.error_description = Some("consent has not been granted".to_string());

    let state = expect_context::<CycloneState>();
    let hydra_config = state.hydra_config();

    match reject_o_auth2_consent_request(&hydra_config, consent_challenge, Some(&body)).await {
        Ok(r) => {
            leptos_axum::redirect(&r.redirect_to);
            Ok(())
        }
        Err(e) => {
            logging::error!("Error: failed to reject consent request: {e}");
            Err(CycloneError::InternalServerError)?
        }
    }
}
