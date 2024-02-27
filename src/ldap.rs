use std::collections::hash_map::Entry;
use std::collections::HashMap;

use ldap3::{Ldap, LdapConnAsync, ResultEntry, Scope, SearchEntry};
use leptos::*;
use regex::{Captures, Regex};
use serde::{Deserialize, Deserializer};

use crate::error::CycloneError;
use crate::server::state::CycloneState;

#[derive(Clone, Debug, Deserialize)]
pub struct LdapConfig {
    /// The LDAP server's URL.
    pub server: String,

    /// The bind DN for binding after establishing the LDAP connection. This identity needs to have
    /// sufficient permissions to perform the necessary LDAP searches.
    pub bind_dn: String,

    /// The bind password for binding after establishing the LDAP connection.
    pub bind_pw: String,

    /// The base DN for searching the user in the LDAP directory.
    pub user_base: String,

    /// The filter for searching the user in the LDAP directory. If multiple search results are
    /// returned, this considered an internal server error. (Multiple results are NOT merged, in
    /// contrast to the extra LDAP searches that can optionally be configured per claim.)
    pub user_filter: String,

    /// Maps OIDC claims to a claim source which specifies how to extract that OIDC claim from the
    /// LDAP directory.
    ///
    ///
    /// a list of LDAP attributes. The given LDAP attributes are searched in
    /// order and the first value found gets assigned to the OIDC claim.
    #[serde(deserialize_with = "parse_claim_source")]
    pub claims: HashMap<String, ClaimSource>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ClaimSource {
    /// If given, specifies a `filter` (and optionally a `base`) that gets used to search the LDAP
    /// directory for this claim. If multiple search results are returned, then they are merged.
    /// When `search` is None, no extra search is performed and the search result from searching the
    /// user is used instead.
    #[serde(flatten)]
    pub search: Option<SearchConfig>,

    /// Specifies how to extract the claim from the LDAP search result.
    #[serde(flatten)]
    pub config: AttrsConfig,
}

#[derive(Clone, Debug, Deserialize)]
pub struct SearchConfig {
    /// The base DN for searching the LDAP directory. When this is none, the `user_base` from the
    /// [`LdapConfig`] is used instead.
    pub base: Option<String>,

    /// The filter for searching the LDAP directory.
    pub filter: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttrsConfig {
    /// The given LDAP attributes are searched in order and the first value found gets assigned to
    /// the OIDC claim. In this case, the OIDC claim's value is a string.
    First(Vec<String>),

    /// The given LDAP attributes' values are concatenated in order into a single list. In this
    /// case, the OIDC claim's value is a list.
    All(Vec<String>),
}

impl AttrsConfig {
    pub fn as_vec(&self) -> &Vec<String> {
        match self {
            AttrsConfig::First(vec) => vec,
            AttrsConfig::All(vec) => vec,
        }
    }
}

fn parse_claim_source<'de, D>(d: D) -> Result<HashMap<String, ClaimSource>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum ClaimSourceOrString {
        ClaimSource(ClaimSource),
        String(String),
    }

    let claims = HashMap::<String, ClaimSourceOrString>::deserialize(d)?;
    Ok(claims
        .into_iter()
        .map(|(claim, val)| {
            let val = match val {
                ClaimSourceOrString::ClaimSource(cs) => cs,
                ClaimSourceOrString::String(str) => ClaimSource {
                    search: None,
                    config: AttrsConfig::First(vec![str]),
                },
            };
            (claim, val)
        })
        .collect())
}

/// Takes the [`CycloneConfig`] from the reactive context, searches the configured LDAP directory
/// for the user specified by `username`, and returns the OIDC claims specified by `scopes`.
///
/// If `check_password` is given, this function also checks the contained password by binding to
/// the user's DN. If the user is not found (This can happen with or without password check) or
/// the password given in `check_password` is incorrect, [`CycloneError::InvalidCredentials`] is
/// returned instead.
pub async fn get_claims_for_scopes(
    username: &str,
    scopes: &[String],
    check_password: Option<&str>,
) -> Result<HashMap<String, serde_json::Value>, CycloneError> {
    let state = expect_context::<CycloneState>();
    let scopes_config = &state.cyclone_config().scopes;

    let mut claim_keys = Vec::new();

    for s in scopes {
        let Some(scope_config) = scopes_config.get(s) else {
            logging::warn!(
                "Warning: requested scope {s} does not exist (i.e., is missing from configuration)"
            );
            continue;
        };

        for key in &scope_config.claims {
            claim_keys.push(key.as_str());
        }
    }

    get_claims(username, &claim_keys, check_password).await
}

/// Takes the [`CycloneConfig`] from the reactive context, searches the configured LDAP directory
/// for the user specified by `username`, and returns the OIDC claims specified by `claim_keys`.
///
/// If `check_password` is given, this function also checks the contained password by binding to
/// the user's DN. If the user is not found (This can happen with or without password check) or
/// the password given in `check_password` is incorrect, [`CycloneError::InvalidCredentials`] is
/// returned instead.
pub async fn get_claims<'a>(
    username: &str,
    claim_keys: &[&str],
    check_password: Option<&str>,
) -> Result<HashMap<String, serde_json::Value>, CycloneError> {
    let state = expect_context::<CycloneState>();
    let ldap_config = &state.cyclone_config().ldap;

    let mut claim_sources = HashMap::new();
    let mut requested_user_attrs = Vec::<&str>::new();
    let mut requested_extra_attrs = HashMap::<(&str, &str), Vec<&str>>::new();

    for &key in claim_keys {
        if let Entry::Vacant(v) = claim_sources.entry(key) {
            let Some(source) = ldap_config.claims.get(key) else {
                logging::error!("Error: no source found for claim {key}");
                continue;
            };

            v.insert(source);

            if let Some(search) = &source.search {
                let base = search.base.as_deref().unwrap_or(&ldap_config.user_base);
                let filter_template = search.filter.as_str();
                for user_attr in get_filter_placeholders(filter_template)? {
                    requested_user_attrs.push(user_attr);
                }
                if let Entry::Vacant(v) = requested_extra_attrs.entry((base, filter_template)) {
                    v.insert(Vec::new());
                }
                let extra_attrs = requested_extra_attrs
                    .get_mut(&(base, filter_template))
                    .unwrap();
                for attr in source.config.as_vec() {
                    extra_attrs.push(attr.as_str());
                }
            } else {
                for attr in source.config.as_vec() {
                    requested_user_attrs.push(attr.as_str());
                }
            }
        }
    }

    let mut ldap = get_ldap(ldap_config).await?;

    let user_attrs = ldap_search_user(
        &mut ldap,
        &ldap_config.user_base,
        &substitute_filter_placeholders(
            &ldap_config.user_filter,
            &HashMap::from([("", username)]),
        )?,
        &requested_user_attrs,
    )
    .await?;

    let mut extra_attrs = HashMap::new();
    for ((base, filter_template), requested_attrs) in requested_extra_attrs {
        let mut substitutions = HashMap::<&str, &str>::new();
        for placeholder in get_filter_placeholders(filter_template)? {
            let Some(instance) = user_attrs.get(placeholder).and_then(|vec| vec.first()) else {
                logging::error!(
                    "Error: attribute {placeholder} (required in filter {filter_template}) missing"
                );
                return Err(CycloneError::InternalServerError);
            };
            substitutions.insert(placeholder, instance);
        }
        let filter = substitute_filter_placeholders(filter_template, &substitutions)?;
        let attrs = ldap_search_and_merge(&mut ldap, base, &filter, &requested_attrs).await?;
        extra_attrs.insert((base, filter_template), attrs);
    }

    let claims = claim_sources
        .into_iter()
        .filter_map(|(key, source)| {
            let attrs = if let Some(search) = &source.search {
                let base = search.base.as_deref().unwrap_or(&ldap_config.user_base);
                let filter_template: &str = &search.filter;
                &extra_attrs[&(base, filter_template)]
            } else {
                &user_attrs
            };
            if let Some(value) = extract_attrs(&source.config, attrs) {
                Some((key.to_string(), value))
            } else {
                None
            }
        })
        .collect();

    // If `check_password` is provided, then we check the password by binding to the user's DN.
    if let Some(password) = check_password {
        let dn = &user_attrs[&"dn".to_string()][0];
        // Bind with the user to check the given password
        if ldap
            .simple_bind(dn, password)
            .await
            .map_err(|e| {
                logging::error!("Error: LDAP connection failed: {e}");
                CycloneError::InternalServerError
            })?
            .success()
            .is_err()
        {
            // Password incorrect
            return Ok(HashMap::new());
        }
    }

    Ok(claims)
}

/// Opens a fresh LDAP connection and binds using `config.bind_dn` and `config.bind_bw`.
async fn get_ldap(config: &LdapConfig) -> Result<Ldap, CycloneError> {
    let (conn, mut ldap) = LdapConnAsync::new(&config.server).await.map_err(|e| {
        logging::error!("Error: failed to initialize LDAP connection: {e}");
        CycloneError::InternalServerError
    })?;
    ldap3::drive!(conn);

    ldap.simple_bind(&config.bind_dn, &config.bind_pw)
        .await
        .map_err(|e| {
            logging::error!("Error: LDAP connection failed: {e}");
            CycloneError::InternalServerError
        })?
        .success()
        .map_err(|e| {
            logging::error!("Error: failed to bind to LDAP (for searching): {e}");
            CycloneError::InternalServerError
        })?;

    Ok(ldap)
}

/// Returns a list of all placeholders contained in `filter_template`. If the template contains any
/// additional curly braces, [`CycloneError::InternalServerError`] is returned instead, as curly
/// braces are reserved for wrapping placeholders. Currently there is no way to escape them.
///
/// Examples:
///
/// ```rust
/// use cyclone::{error::CycloneError, ldap::get_filter_placeholders};
/// assert_eq!(get_filter_placeholders("foo {abc} bar {xyz} baz"), Ok(vec!["abc", "xyz"]));
/// assert_eq!(get_filter_placeholders("foo {"), Err(CycloneError::InternalServerError));
/// assert_eq!(get_filter_placeholders("foo {abc}}"), Err(CycloneError::InternalServerError));
/// ```
pub fn get_filter_placeholders(filter_template: &str) -> Result<Vec<&str>, CycloneError> {
    let regex_str = "(\\{[^\\{\\}]*\\}|\\{|\\})";
    let regex = Regex::new(regex_str).unwrap();
    let mut res = Vec::new();
    for cap in regex.find_iter(filter_template) {
        let cap = cap.as_str();
        if cap == "{" || cap == "}" {
            logging::error!("Error: syntax error in filter {filter_template}");
            return Err(CycloneError::InternalServerError);
        }
        let mut chars = cap.chars();
        chars.next();
        chars.next_back();
        let placeholder = chars.as_str();
        res.push(placeholder);
    }
    Ok(res)
}

/// Substitutes any placeholders (see [`get_filter_placeholders`]) in `filter_template` by their
/// respective value in `substitutions`. Furthermore, this functions escapes all substituted values
/// using [`ldap3::ldap_escape`]. If a placeholder is missing (as a key) in `substitutions`
/// or if the template contains any additional curly braces, [`CycloneError::InternalServerError`]
/// is returned instead.
///
/// Example:
///
/// ```rust
/// use {cyclone::{error::CycloneError, ldap::substitute_filter_placeholders}, std::collections::HashMap};
/// let subst = &HashMap::from([("abc", "ABC("), ("xyz", ")XYZ")]);
///
/// let actual = substitute_filter_placeholders("foo {abc} bar {xyz} baz", subst);
/// let expected = Ok("foo ABC\\28 bar \\29XYZ baz".to_string()); // Note the LDAP escaping
/// assert_eq!(actual, expected);
///
/// let actual = substitute_filter_placeholders("foo {abc} bar {dummy} baz", subst);
/// let expected = Err(CycloneError::InternalServerError); // Because "dummy" not in `subst`
/// assert_eq!(actual, expected);
///
/// let actual = substitute_filter_placeholders("foo {", subst);
/// let expected = Err(CycloneError::InternalServerError); // Due to syntax error
/// assert_eq!(actual, expected);
/// ```
pub fn substitute_filter_placeholders(
    filter_template: &str,
    substitutions: &HashMap<&str, &str>,
) -> Result<String, CycloneError> {
    let regex_str = "(\\{[^\\{\\}]*\\}|\\{|\\})";
    let regex = Regex::new(regex_str).unwrap();
    let mut res = Ok(());
    let filter = regex.replace_all(filter_template, |cap: &Captures| {
        let cap = &cap[0];
        if cap.len() < 2 {
            logging::error!("Error: syntax error in filter {filter_template}");
            res = Err(CycloneError::InternalServerError);
            return String::new();
        }
        let mut chars = cap.chars();
        chars.next();
        chars.next_back();
        let placeholder = chars.as_str();
        let Some(&instance) = substitutions.get(placeholder) else {
            logging::error!(
                "Error: unsupported placeholder {placeholder} in filter {filter_template}"
            );
            res = Err(CycloneError::InternalServerError);
            return String::new();
        };
        ldap3::ldap_escape(instance).to_string()
    });
    res.map(|_| filter.to_string())
}

/// Performs an LDAP search on the subtree of `base` and merges the resulting attribute sets. Note
/// that no error is returned when certain requested attributes are missing from the result.
async fn ldap_search_and_merge(
    ldap: &mut Ldap,
    base: &str,
    filter: &str,
    requested_attrs: &[&str],
) -> Result<HashMap<String, Vec<String>>, CycloneError> {
    let rs = ldap_search(ldap, base, filter, requested_attrs).await?;
    let mut attrs = HashMap::<String, Vec<String>>::new();
    for r in rs {
        let entry = SearchEntry::construct(r);
        for (key, values) in entry.attrs {
            if let Entry::Vacant(v) = attrs.entry(key.clone()) {
                v.insert(Vec::new());
            }
            let all_values = attrs.get_mut(&key).unwrap();
            for val in values {
                all_values.push(val);
            }
        }
    }
    Ok(attrs)
}

/// Performs an LDAP search on the subtree of `base` and expects exactly one result.
///
/// - When the search returns more than one result, [`CycloneError::InternalServerError`]
///   is returned instead.
/// - When the search returns no result, [`CycloneError::InvalidCredentials`] is returned
///   instead.
///
/// This error behavior makes this function suitable for searching users in LDAP. Note that no
/// error is returned when certain requested attributes are missing from the result.
async fn ldap_search_user(
    ldap: &mut Ldap,
    base: &str,
    filter: &str,
    requested_attrs: &[&str],
) -> Result<HashMap<String, Vec<String>>, CycloneError> {
    let rs = ldap_search(ldap, base, filter, requested_attrs).await?;

    if rs.len() > 1 {
        logging::error!("Error: multiple results for filter {filter}");
        return Err(CycloneError::InternalServerError.into());
    }

    let Some(entry) = rs.into_iter().next().map(SearchEntry::construct) else {
        return Err(CycloneError::InvalidCredentials.into());
    };

    let mut attrs = entry.attrs;
    attrs.insert("dn".to_string(), vec![entry.dn]);
    Ok(attrs)
}

/// Performs an LDAP search on the subtree of `base`. Note that no error is returned when certain
/// requested attributes are missing from the result.
async fn ldap_search(
    ldap: &mut Ldap,
    base: &str,
    filter: &str,
    requested_attrs: &[&str],
) -> Result<Vec<ResultEntry>, CycloneError> {
    let (rs, _res) = ldap
        .search(&base, Scope::Subtree, &filter, requested_attrs)
        .await
        .map_err(|e| {
            logging::error!("Error: LDAP connection failed: {e}");
            CycloneError::InternalServerError
        })?
        .success()
        .map_err(|e| {
            logging::error!("Error: failed to search LDAP: {e}");
            CycloneError::InternalServerError
        })?;
    Ok(rs)
}

fn extract_attrs(
    config: &AttrsConfig,
    attrs: &HashMap<String, Vec<String>>,
) -> Option<serde_json::Value> {
    match config {
        AttrsConfig::First(keys) => {
            for key in keys {
                if let Some(value) = attrs.get(key).and_then(|vec| vec.first()) {
                    return Some(serde_json::json!(value));
                }
            }
            None
        }
        AttrsConfig::All(keys) => {
            let empty_vec = Vec::new();
            let values: Vec<&String> = keys
                .iter()
                .map(|key| attrs.get(key).unwrap_or(&empty_vec))
                .flatten()
                .collect();
            Some(serde_json::json!(values))
        }
    }
}
