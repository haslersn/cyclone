use std::time::Duration;

use leptos::*;
use ory_hydra_client::apis::configuration::Configuration;
use ory_hydra_client::apis::o_auth2_api::{
    GetOAuth2ConsentRequestError, GetOAuth2LoginRequestError,
};
use ory_hydra_client::apis::Error;
use reqwest::Url;
use serde::{Deserialize, Deserializer};

use crate::error::CycloneError;

#[derive(Clone, Debug, Deserialize)]
pub struct HydraConfig {
    #[serde(deserialize_with = "parse_url")]
    pub url: Url,
    #[serde(deserialize_with = "parse_duration")]
    pub session_ttl: Duration,
}

impl Into<Configuration> for &HydraConfig {
    fn into(self) -> Configuration {
        Configuration {
            base_path: self.url.to_string(),
            user_agent: None,
            client: reqwest::Client::new(),
            basic_auth: None,
            oauth_access_token: None,
            bearer_access_token: None,
            api_key: None,
        }
    }
}

fn parse_url<'de, D>(d: D) -> Result<Url, D::Error>
where
    D: Deserializer<'de>,
{
    let buf = String::deserialize(d)?;
    Url::try_from(buf.as_str()).map_err(serde::de::Error::custom)
}

fn parse_duration<'de, D>(d: D) -> Result<Duration, D::Error>
where
    D: Deserializer<'de>,
{
    let buf = String::deserialize(d)?;
    buf.parse::<humantime::Duration>()
        .map_err(serde::de::Error::custom)
        .map(Into::into)
}

pub fn map_get_login_request_error(e: Error<GetOAuth2LoginRequestError>) -> CycloneError {
    if let Error::ResponseError(rc) = e {
        let msg = match rc.entity {
            Some(GetOAuth2LoginRequestError::DefaultResponse(e_oauth2)) => {
                e_oauth2.error_description.unwrap_or(rc.content)
            }
            _ => rc.content,
        };
        CycloneError::GetOAuth2LoginRequestError(msg)
    } else {
        logging::error!("Error: failed to get login request: {}", e);
        CycloneError::InternalServerError
    }
}

pub fn map_get_consent_request_error(e: Error<GetOAuth2ConsentRequestError>) -> CycloneError {
    if let Error::ResponseError(rc) = e {
        let msg = match rc.entity {
            Some(GetOAuth2ConsentRequestError::DefaultResponse(e_oauth2)) => {
                e_oauth2.error_description.unwrap_or(rc.content)
            }
            _ => rc.content,
        };
        CycloneError::GetOAuth2ConsentRequestError(msg)
    } else {
        logging::error!("Error: failed to get consent request: {}", e);
        CycloneError::InternalServerError
    }
}
