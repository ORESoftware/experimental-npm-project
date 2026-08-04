//! Thin typed client for the shared-auth server (see ../../ENDPOINTS.md).
//!
//! Verbs only — guard logic (the dual-auth race, limited HTML) lives in
//! shared-auth-lib. This crate is for services that need to call the API with
//! bounded transport defaults and, where configured, an authenticated
//! introspection credential.

use std::{net::IpAddr, sync::Arc, time::Duration};

use reqwest::{
    header::{ACCEPT, CONTENT_TYPE},
    redirect::Policy,
    Method, RequestBuilder, Response,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use url::Url;

const DEFAULT_MAX_REQUEST_BYTES: usize = 256 * 1024;
const DEFAULT_MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_CREDENTIAL_BYTES: usize = 16 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// Uniform 401 from the server.
    #[error("unauthorized")]
    Unauthorized,
    /// Protected introspection was called without the independent service
    /// credential. No HTTP request was attempted.
    #[error("introspection service credential is required")]
    MissingServiceCredential,
    #[error("invalid shared-auth base URL")]
    InvalidBaseUrl,
    #[error("invalid {0}")]
    InvalidInput(&'static str),
    #[error("request body exceeds {limit} bytes")]
    RequestTooLarge { limit: usize },
    #[error("response body exceeds {limit} bytes")]
    ResponseTooLarge { limit: usize },
    #[error("request JSON encoding failed")]
    Encode {
        #[source]
        source: serde_json::Error,
    },
    #[error("response JSON decoding failed")]
    Decode {
        #[source]
        source: serde_json::Error,
    },
    #[error("transport failed")]
    Transport(#[from] reqwest::Error),
    #[error("unexpected status {0}")]
    Status(u16),
}

#[derive(Clone, Debug, Deserialize)]
pub struct ExchangeResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_at: u64,
    pub shared_user_id: String,
    #[serde(default)]
    pub project: Option<String>,
    #[serde(default)]
    pub provider: Option<String>,
    #[serde(default)]
    pub provider_tenant: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct StepUpResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_at: u64,
    #[serde(default)]
    pub amr: Vec<String>,
    #[serde(default)]
    pub acr: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Introspection {
    pub active: bool,
    #[serde(default)]
    pub sub: Option<String>,
    #[serde(default)]
    pub sid: Option<String>,
    #[serde(default)]
    pub project: Option<String>,
    #[serde(default)]
    pub provider: Option<String>,
    #[serde(default)]
    pub provider_tenant: Option<String>,
    #[serde(default)]
    pub provider_subject: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub email_verified: Option<bool>,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub amr: Vec<String>,
    #[serde(default)]
    pub acr: Option<String>,
    #[serde(default)]
    pub exp: Option<u64>,
    #[serde(flatten)]
    pub rest: serde_json::Map<String, serde_json::Value>,
}

impl Introspection {
    /// Missing legacy assurance claims never satisfy an explicit policy.
    pub fn has_acr(&self, required: &str) -> bool {
        self.active && self.acr.as_deref() == Some(required)
    }

    pub fn used_method(&self, method: &str) -> bool {
        self.active && self.amr.iter().any(|candidate| candidate == method)
    }

    pub fn has_role(&self, role: &str) -> bool {
        self.active && self.roles.iter().any(|candidate| candidate == role)
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct Capabilities {
    pub mfa_enabled: bool,
    #[serde(default)]
    pub methods: Vec<String>,
    #[serde(default)]
    pub threefa_import_scheme: Option<String>,
    #[serde(default)]
    pub biometric_model: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Factor {
    pub factor_id: String,
    pub kind: String,
    #[serde(default)]
    pub label: Option<String>,
    pub enabled: bool,
    #[serde(default)]
    pub confirmed_at: Option<String>,
    #[serde(default)]
    pub last_used_at: Option<String>,
    pub created_at: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct TotpEnrollment {
    pub factor_id: String,
    pub secret_base32: String,
    pub otpauth_uri: String,
    pub threefa_import_uri: String,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeKind {
    EmailOtp,
    SmsOtp,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ChallengeStart {
    pub challenge_id: String,
    pub expires_at: String,
    pub delivery: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct CeremonyStart {
    pub challenge_id: String,
    pub options: serde_json::Value,
    pub expires_at: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct TotpEnrollRequest<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<&'a str>,
}

#[derive(Clone, Debug, Serialize)]
pub struct TotpConfirmRequest<'a> {
    pub factor_id: &'a str,
    pub code: &'a str,
}

#[derive(Clone, Debug, Serialize)]
pub struct PasskeyRegistrationFinish<'a> {
    pub challenge_id: &'a str,
    pub credential: &'a serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<&'a str>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PasskeyAuthenticationFinish<'a> {
    pub challenge_id: &'a str,
    pub credential: &'a serde_json::Value,
}

#[derive(Clone)]
enum BaseUrl {
    Valid(Url),
    Invalid,
}

#[derive(Clone)]
pub struct SharedAuthClient {
    base: BaseUrl,
    http: reqwest::Client,
    service_credential: Option<Arc<str>>,
    max_request_bytes: usize,
    max_response_bytes: usize,
}

impl SharedAuthClient {
    /// `base` is the mounted prefix, e.g. `https://gateway/shared-auth`.
    ///
    /// The default transport refuses redirects and bounds connect/request time so    /// an auth dependency cannot occupy a task indefinitely.
    pub fn new(base: impl Into<String>) -> Self {
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(5))
            .redirect(Policy::none())
            .user_agent("shared-auth-client-rust/0.1")
            .build()
            .expect("static shared-auth HTTP client configuration is valid");
        Self::with_http(base, http)
    }

    pub fn with_http(base: impl Into<String>, http: reqwest::Client) -> Self {
        Self {
            base: match normalize_base(&base.into()) {
                Ok(base) => BaseUrl::Valid(base),
                Err(()) => BaseUrl::Invalid,
            },
            http,
            service_credential: None,
            max_request_bytes: DEFAULT_MAX_REQUEST_BYTES,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
        }
    }

    /// Attach the service-to-service bearer required by protected introspection.
    /// The credential is never used for end-user exchange, verification, or MFA
    /// endpoints, where the caller's own access token remains authoritative.
    pub fn with_service_credential(mut self, credential: impl Into<String>) -> Self {
        self.service_credential = Some(Arc::<str>::from(credential.into()));
        self
    }

    pub fn without_service_credential(mut self) -> Self {
        self.service_credential = None;
        self
    }

    pub fn with_max_request_bytes(mut self, limit: usize) -> Self {
        self.max_request_bytes = limit;
        self
    }

    pub fn with_max_response_bytes(mut self, limit: usize) -> Self {
        self.max_response_bytes = limit;
        self
    }

    /// Supabase access token → shared-auth token.
    pub async fn exchange(&self, supabase_token: &str) -> Result<ExchangeResponse, ClientError> {
        let request = self.request(Method::POST, &["auth", "exchange"])?;
        let request = with_bearer(request, supabase_token, "Supabase token")?;
        self.send_json(request).await
    }

    /// RFC-7662-shaped protected introspection of a shared-auth token.
    ///
    /// Missing service credentials fail locally before request construction,
    /// separating deployment drift from invalid end-user tokens.
    pub async fn introspect(&self, token: &str) -> Result<Introspection, ClientError> {
        let credential = self
            .service_credential
            .as_deref()
            .ok_or(ClientError::MissingServiceCredential)?;
        let credential = required_credential(credential, "service credential")?;
        let token = required_credential(token, "token")?;
        let request = self.request(Method::POST, &["auth", "introspect"])?;
        let request = self.with_json(request, &serde_json::json!({ "token": token }))?;
        let request = with_bearer(request, credential, "service credential")?;
        self.send_json(request).await
    }

    /// Lightweight bearer check (the gateway `auth_request` endpoint).
    pub async fn verify(&self, token: &str) -> Result<bool, ClientError> {
        let request = self.request(Method::GET, &["auth", "verify"])?;
        let request = with_bearer(request, token, "token")?;
        let response = request.send().await?;
        match response.status().as_u16() {
            200 => Ok(true),
            401 => Ok(false),
            code => Err(ClientError::Status(code)),
        }
    }

    /// The server's public JWKS (for local verification via shared-auth-lib).
    pub async fn jwks(&self) -> Result<serde_json::Value, ClientError> {
        let request = self.request(Method::GET, &[".well-known", "jwks.json"])?;
        self.send_json(request).await
    }

    pub async fn capabilities(&self) -> Result<Capabilities, ClientError> {
        let request = self.request(Method::GET, &["auth", "capabilities"])?;
        self.send_json(request).await
    }

    pub async fn factors(&self, access_token: &str) -> Result<Vec<Factor>, ClientError> {
        self.authed_json(Method::GET, &["auth", "factors"], access_token, None::<&()>)
            .await
    }

    pub async fn enroll_totp(
        &self,
        access_token: &str,
        label: Option<&str>,
    ) -> Result<TotpEnrollment, ClientError> {
        self.authed_json(
            Method::POST,
            &["auth", "factors", "totp", "enroll"],
            access_token,
            Some(&TotpEnrollRequest { label }),
        )
        .await
    }

    pub async fn confirm_totp(
        &self,
        access_token: &str,
        factor_id: &str,
        code: &str,
    ) -> Result<StepUpResponse, ClientError> {
        let factor_id = required_field(factor_id, "factor ID")?;
        let code = required_field(code, "TOTP code")?;
        self.authed_json(
            Method::POST,
            &["auth", "factors", "totp", "confirm"],
            access_token,
            Some(&TotpConfirmRequest { factor_id, code }),
        )
        .await
    }

    pub async fn delete_factor(
        &self,
        access_token: &str,
        factor_id: &str,
    ) -> Result<(), ClientError> {
        let factor_id = required_field(factor_id, "factor ID")?;
        let request = self.request(Method::DELETE, &["auth", "factors", factor_id])?;
        let request = with_bearer(request, access_token, "access token")?;
        decode_empty(request.send().await?)
    }

    pub async fn create_challenge(
        &self,
        access_token: &str,
        kind: ChallengeKind,
    ) -> Result<ChallengeStart, ClientError> {
        self.authed_json(
            Method::POST,
            &["auth", "challenges"],
            access_token,
            Some(&serde_json::json!({ "kind": kind })),
        )
        .await
    }

    pub async fn verify_challenge(
        &self,
        access_token: &str,
        challenge_id: &str,
        code: &str,
    ) -> Result<StepUpResponse, ClientError> {
        let challenge_id = required_field(challenge_id, "challenge ID")?;
        let code = required_field(code, "challenge code")?;
        self.authed_json(
            Method::POST,
            &["auth", "challenges", challenge_id, "verify"],
            access_token,
            Some(&serde_json::json!({ "code": code })),
        )
        .await
    }

    pub async fn start_passkey_registration(
        &self,
        access_token: &str,
        label: Option<&str>,
    ) -> Result<CeremonyStart, ClientError> {
        self.authed_json(
            Method::POST,
            &["auth", "passkeys", "registration", "options"],
            access_token,
            Some(&serde_json::json!({ "label": label })),
        )
        .await
    }

    pub async fn finish_passkey_registration(
        &self,
        access_token: &str,
        challenge_id: &str,
        credential: &serde_json::Value,
        label: Option<&str>,
    ) -> Result<Factor, ClientError> {
        let challenge_id = required_field(challenge_id, "challenge ID")?;
        self.authed_json(
            Method::POST,
            &["auth", "passkeys", "registration", "verify"],
            access_token,
            Some(&PasskeyRegistrationFinish {
                challenge_id,
                credential,
                label,
            }),
        )
        .await
    }

    pub async fn start_passkey_authentication(
        &self,
        access_token: &str,
    ) -> Result<CeremonyStart, ClientError> {
        self.authed_json(
            Method::POST,
            &["auth", "passkeys", "authentication", "options"],
            access_token,
            Some(&serde_json::json!({})),
        )
        .await
    }

    pub async fn finish_passkey_authentication(
        &self,
        access_token: &str,
        challenge_id: &str,
        credential: &serde_json::Value,
    ) -> Result<StepUpResponse, ClientError> {
        let challenge_id = required_field(challenge_id, "challenge ID")?;
        self.authed_json(
            Method::POST,
            &["auth", "passkeys", "authentication", "verify"],
            access_token,
            Some(&PasskeyAuthenticationFinish {
                challenge_id,
                credential,
            }),
        )
        .await
    }

    async fn authed_json<T, B>(
        &self,
        method: Method,
        segments: &[&str],
        access_token: &str,
        body: Option<&B>,
    ) -> Result<T, ClientError>
    where
        T: DeserializeOwned,
        B: Serialize + ?Sized,
    {
        let request = self.request(method, segments)?;
        let request = with_bearer(request, access_token, "access token")?;
        let request = match body {
            Some(body) => self.with_json(request, body)?,
            None => request,
        };
        self.send_json(request).await
    }

    fn request(&self, method: Method, segments: &[&str]) -> Result<RequestBuilder, ClientError> {
        Ok(self
            .http
            .request(method, self.endpoint(segments)?)
            .header(ACCEPT, "application/json"))
    }

    fn endpoint(&self, segments: &[&str]) -> Result<Url, ClientError> {
        let mut url = match &self.base {
            BaseUrl::Valid(url) => url.clone(),
            BaseUrl::Invalid => return Err(ClientError::InvalidBaseUrl),
        };
        {
            let mut path = url
                .path_segments_mut()
                .map_err(|()| ClientError::InvalidBaseUrl)?;
            path.pop_if_empty();
            for segment in segments {
                validate_path_segment(segment)?;
                path.push(segment);
            }
        }
        Ok(url)
    }

    fn with_json<B: Serialize + ?Sized>(
        &self,
        request: RequestBuilder,
        body: &B,
    ) -> Result<RequestBuilder, ClientError> {
        let encoded = serde_json::to_vec(body).map_err(|source| ClientError::Encode { source })?;
        if encoded.len() > self.max_request_bytes {
            return Err(ClientError::RequestTooLarge {
                limit: self.max_request_bytes,
            });
        }
        Ok(request
            .header(CONTENT_TYPE, "application/json")
            .body(encoded))
    }

    async fn send_json<T: DeserializeOwned>(
        &self,
        request: RequestBuilder,
    ) -> Result<T, ClientError> {
        decode_json(request.send().await?, self.max_response_bytes).await
    }
}

fn normalize_base(base: &str) -> Result<Url, ()> {
    let mut url = Url::parse(base.trim()).map_err(|_| ())?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.cannot_be_a_base()
    {
        return Err(());
    }
    if url.scheme() == "http" && !is_loopback(&url) {
        return Err(());
    }

    let normalized_path = url.path().trim_end_matches('/').to_owned();
    url.set_path(if normalized_path.is_empty() {
        "/"
    } else {
        &normalized_path
    });
    Ok(url)
}

fn is_loopback(url: &Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    let normalized = host.trim_end_matches('.');
    normalized.eq_ignore_ascii_case("localhost")
        || normalized
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn with_bearer(
    request: RequestBuilder,
    credential: &str,
    field: &'static str,
) -> Result<RequestBuilder, ClientError> {
    Ok(request.bearer_auth(required_credential(credential, field)?))
}

fn required_credential<'a>(value: &'a str, field: &'static str) -> Result<&'a str, ClientError> {
    if value.is_empty()
        || value.trim() != value
        || value.chars().any(char::is_whitespace)
        || value.chars().any(char::is_control)
        || value.len() > MAX_CREDENTIAL_BYTES
    {
        return Err(ClientError::InvalidInput(field));
    }
    Ok(value)
}

fn required_field<'a>(value: &'a str, field: &'static str) -> Result<&'a str, ClientError> {
    if value.is_empty()
        || value.trim() != value
        || value.chars().any(char::is_control)
        || value.len() > MAX_CREDENTIAL_BYTES
        || matches!(value, "." | "..")
    {
        return Err(ClientError::InvalidInput(field));
    }
    Ok(value)
}

fn validate_path_segment(segment: &str) -> Result<(), ClientError> {
    if segment.is_empty() || segment.chars().any(char::is_control) || matches!(segment, "." | "..")
    {
        return Err(ClientError::InvalidInput("path segment"));
    }
    Ok(())
}

async fn decode_json<T: DeserializeOwned>(
    mut response: Response,
    max_response_bytes: usize,
) -> Result<T, ClientError> {
    match response.status().as_u16() {
        200..=299 => {}
        401 => return Err(ClientError::Unauthorized),
        code => return Err(ClientError::Status(code)),
    }

    let max_response_bytes_u64 = u64::try_from(max_response_bytes).unwrap_or(u64::MAX);
    if response
        .content_length()
        .is_some_and(|length| length > max_response_bytes_u64)
    {
        return Err(ClientError::ResponseTooLarge {
            limit: max_response_bytes,
        });
    }

    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        let next_len =
            body.len()
                .checked_add(chunk.len())
                .ok_or(ClientError::ResponseTooLarge {
                    limit: max_response_bytes,
                })?;
        if next_len > max_response_bytes {
            return Err(ClientError::ResponseTooLarge {
                limit: max_response_bytes,
            });
        }
        body.extend_from_slice(&chunk);
    }

    serde_json::from_slice(&body).map_err(|source| ClientError::Decode { source })
}

fn decode_empty(response: Response) -> Result<(), ClientError> {
    match response.status().as_u16() {
        200..=299 => Ok(()),
        401 => Err(ClientError::Unauthorized),
        code => Err(ClientError::Status(code)),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
    };

    use super::*;

    #[test]
    fn base_url_is_normalized_and_dynamic_segments_are_encoded() {
        let client = SharedAuthClient::new(" https://gw.example/shared-auth/// ");
        let endpoint = client
            .endpoint(&["auth", "factors", "factor/one%two"])
            .unwrap();
        assert_eq!(
            endpoint.as_str(),
            "https://gw.example/shared-auth/auth/factors/factor%2Fone%25two"
        );
    }

    #[tokio::test]
    async fn invalid_and_remote_plaintext_base_urls_fail_before_transport() {
        for base in [
            "relative/path",
            "ftp://gw.example/shared-auth",
            "http://gw.example/shared-auth",
            "https://user:secret@gw.example/shared-auth",
            "https://gw.example/shared-auth?tenant=one",
        ] {
            let error = SharedAuthClient::new(base).jwks().await.unwrap_err();
            assert!(matches!(error, ClientError::InvalidBaseUrl), "{base}");
        }
    }

    #[test]
    fn assurance_checks_fail_closed() {
        let inactive = Introspection {
            active: false,
            sub: None,
            sid: None,
            project: None,
            provider: None,
            provider_tenant: None,
            provider_subject: None,
            email: None,
            email_verified: None,
            roles: vec!["admin".into()],
            amr: vec!["passkey".into()],
            acr: Some("urn:oresoftware:loa:2".into()),
            exp: None,
            rest: Default::default(),
        };
        assert!(!inactive.has_acr("urn:oresoftware:loa:2"));
        assert!(!inactive.used_method("passkey"));
        assert!(!inactive.has_role("admin"));
    }

    #[tokio::test]
    async fn malformed_credentials_fail_before_transport() {
        let client = SharedAuthClient::new("http://127.0.0.1:1");
        let error = client.exchange(" token ").await.unwrap_err();
        assert!(matches!(error, ClientError::InvalidInput("Supabase token")));

        let error = client
            .clone()
            .with_service_credential("secret\nheader")
            .introspect("token")
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            ClientError::InvalidInput("service credential")
        ));
    }

    #[tokio::test]
    async fn request_bodies_are_bounded_before_transport() {
        let client = SharedAuthClient::new("http://127.0.0.1:1").with_max_request_bytes(32);
        let credential = serde_json::json!({ "padding": "x".repeat(128) });
        let error = client
            .finish_passkey_authentication("token", "challenge", &credential)
            .await
            .unwrap_err();
        assert!(matches!(error, ClientError::RequestTooLarge { limit: 32 }));
    }

    #[tokio::test]
    async fn response_bodies_are_bounded_before_decode() {
        let body =
            br#"{"padding":"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}"#;
        let base = spawn_single_response(body);
        let client = SharedAuthClient::new(base).with_max_response_bytes(16);
        let error = client.jwks().await.unwrap_err();
        assert!(matches!(error, ClientError::ResponseTooLarge { limit: 16 }));
    }

    #[tokio::test]
    async fn transport_display_is_redacted() {
        let client = SharedAuthClient::new("http://127.0.0.1:1");
        let error = client.exchange("token").await.unwrap_err();
        assert!(matches!(error, ClientError::Transport(_)));
        assert_eq!(error.to_string(), "transport failed");
    }

    fn spawn_single_response(body: &'static [u8]) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 2048];
            let _ = stream.read(&mut request);
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .unwrap();
            stream.write_all(body).unwrap();
        });
        format!("http://{address}")
    }
}
