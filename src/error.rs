use leptos::*;
use serde::{Deserialize, Serialize};
use strum::{Display, EnumString};
use thiserror::Error;

#[derive(Clone, Debug, EnumString, Display, Error, Serialize, Deserialize, PartialEq)]
pub enum CycloneError {
    NotFound,
    InternalServerError,
    InvalidCredentials,
    LoginChallengeMissing,
    ConsentChallengeMissing,
    GetOAuth2LoginRequestError(String),
    GetOAuth2ConsentRequestError(String),
}

#[component]
pub fn ErrorTemplate(#[prop()] errors: Signal<Errors>) -> impl IntoView {
    move || {
        errors
            .get()
            .iter()
            .map(|(_key, error)| {
                let error_string =
                    if let Some(ServerFnError::WrappedServerError::<CycloneError>(ce)) =
                        error.downcast_ref::<leptos::ServerFnError<CycloneError>>()
                    {
                        format!("{ce:?}")
                    } else {
                        format!("{error:?}")
                    };
                view! { <div class="error">{error_string}</div> }
            })
            .collect_view()
    }
}
