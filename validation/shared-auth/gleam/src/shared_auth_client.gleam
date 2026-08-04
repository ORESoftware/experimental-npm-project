//// Thin, typed Gleam client for the shared-auth HTTP API.
////
//// Guard orchestration, the dual-auth race, and limited HTML remain in
//// shared-auth-lib. This module implements transport verbs only.

import gleam/dynamic/decode
import gleam/http
import gleam/http/request.{type Request}
import gleam/http/response.{type Response}
import gleam/httpc
import gleam/json
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import gleam/uri
import shared_auth_client/model.{
  type Capabilities, type CeremonyStart, type ChallengeKind, type ChallengeStart,
  type ExchangeResponse, type Factor, type Introspection, type Jwks,
  type StepUpResponse, type TotpEnrollment,
}

pub type ClientError {
  Unauthorized
  MissingServiceCredential
  UnexpectedStatus(status: Int)
  InvalidUrl
  InvalidTimeout
  InvalidResponse(error: json.DecodeError)
  TransportError(error: httpc.HttpError)
}

/// Injectable transport used for deterministic tests and alternate runtimes.
pub type Transport =
  fn(Request(String), Int) -> Result(Response(String), httpc.HttpError)

pub opaque type Client {
  Client(
    base: String,
    service_credential: Option(String),
    timeout_ms: Int,
    transport: Transport,
  )
}

/// Construct a client with TLS verification, redirects disabled, and a
/// ten-second response deadline.
pub fn new(base: String) -> Result(Client, ClientError) {
  let base = normalize_base(base)
  case request.to(base <> "/healthz") {
    Ok(_) ->
      Ok(Client(
        base: base,
        service_credential: None,
        timeout_ms: 10_000,
        transport: default_transport,
      ))
    Error(_) -> Error(InvalidUrl)
  }
}

/// Attach the service bearer used only by protected introspection.
pub fn with_service_credential(client: Client, credential: String) -> Client {
  Client(
    ..client,
    service_credential: credential |> string.trim |> string.to_option,
  )
}

pub fn without_service_credential(client: Client) -> Client {
  Client(..client, service_credential: None)
}

pub fn with_timeout(
  client: Client,
  timeout_ms: Int,
) -> Result(Client, ClientError) {
  case timeout_ms > 0 {
    True -> Ok(Client(..client, timeout_ms: timeout_ms))
    False -> Error(InvalidTimeout)
  }
}

pub fn with_transport(client: Client, transport: Transport) -> Client {
  Client(..client, transport: transport)
}

pub fn has_assurance(value: Introspection, required_acr: String) -> Bool {
  model.has_assurance(value, required_acr)
}

pub fn used_method(value: Introspection, method: String) -> Bool {
  model.used_method(value, method)
}

pub fn has_role(value: Introspection, role: String) -> Bool {
  model.has_role(value, role)
}

/// Supabase access token to shared-auth access token.
pub fn exchange(
  client: Client,
  supabase_token: String,
) -> Result(ExchangeResponse, ClientError) {
  request_json(
    client,
    http.Post,
    "/auth/exchange",
    Some(supabase_token),
    None,
    model.exchange_response_decoder(),
  )
}

/// RFC-7662-shaped protected introspection.
pub fn introspect(
  client: Client,
  token: String,
) -> Result(Introspection, ClientError) {
  case client.service_credential {
    None -> Error(MissingServiceCredential)
    Some(service_credential) ->
      request_json(
        client,
        http.Post,
        "/auth/introspect",
        Some(service_credential),
        Some(json.object([#("token", json.string(token))])),
        model.introspection_decoder(),
      )
  }
}

/// Lightweight bearer verification for gateway auth_request integrations.
pub fn verify(client: Client, token: String) -> Result(Bool, ClientError) {
  use req <- result.try(build_request(
    client,
    http.Get,
    "/auth/verify",
    Some(token),
    None,
  ))
  use response <- result.try(send(client, req))
  case response.status {
    200 -> Ok(True)
    401 -> Ok(False)
    status -> Error(UnexpectedStatus(status))
  }
}

pub fn jwks(client: Client) -> Result(Jwks, ClientError) {
  request_json(
    client,
    http.Get,
    "/.well-known/jwks.json",
    None,
    None,
    model.jwks_decoder(),
  )
}

pub fn capabilities(client: Client) -> Result(Capabilities, ClientError) {
  request_json(
    client,
    http.Get,
    "/auth/capabilities",
    None,
    None,
    model.capabilities_decoder(),
  )
}

pub fn factors(
  client: Client,
  access_token: String,
) -> Result(List(Factor), ClientError) {
  request_json(
    client,
    http.Get,
    "/auth/factors",
    Some(access_token),
    None,
    decode.list(model.factor_decoder()),
  )
}

pub fn enroll_totp(
  client: Client,
  access_token: String,
  label: Option(String),
) -> Result(TotpEnrollment, ClientError) {
  request_json(
    client,
    http.Post,
    "/auth/factors/totp/enroll",
    Some(access_token),
    Some(json.object(optional_string_field("label", label))),
    model.totp_enrollment_decoder(),
  )
}

pub fn confirm_totp(
  client: Client,
  access_token: String,
  factor_id: String,
  code: String,
) -> Result(StepUpResponse, ClientError) {
  request_json(
    client,
    http.Post,
    "/auth/factors/totp/confirm",
    Some(access_token),
    Some(
      json.object([
        #("factor_id", json.string(factor_id)),
        #("code", json.string(code)),
      ]),
    ),
    model.step_up_response_decoder(),
  )
}

pub fn delete_factor(
  client: Client,
  access_token: String,
  factor_id: String,
) -> Result(Nil, ClientError) {
  let path = "/auth/factors/" <> uri.percent_encode(factor_id)
  request_empty(client, http.Delete, path, Some(access_token), None)
}

pub fn create_challenge(
  client: Client,
  access_token: String,
  kind: ChallengeKind,
) -> Result(ChallengeStart, ClientError) {
  request_json(
    client,
    http.Post,
    "/auth/challenges",
    Some(access_token),
    Some(
      json.object([
        #("kind", kind |> model.challenge_kind_to_string |> json.string),
      ]),
    ),
    model.challenge_start_decoder(),
  )
}

pub fn verify_challenge(
  client: Client,
  access_token: String,
  challenge_id: String,
  code: String,
) -> Result(StepUpResponse, ClientError) {
  let path =
    "/auth/challenges/" <> uri.percent_encode(challenge_id) <> "/verify"
  request_json(
    client,
    http.Post,
    path,
    Some(access_token),
    Some(json.object([#("code", json.string(code))])),
    model.step_up_response_decoder(),
  )
}

pub fn start_passkey_registration(
  client: Client,
  access_token: String,
  label: Option(String),
) -> Result(CeremonyStart, ClientError) {
  request_json(
    client,
    http.Post,
    "/auth/passkeys/registration/options",
    Some(access_token),
    Some(json.object(optional_string_field("label", label))),
    model.ceremony_start_decoder(),
  )
}

pub fn finish_passkey_registration(
  client: Client,
  access_token: String,
  challenge_id: String,
  credential: json.Json,
  label: Option(String),
) -> Result(Factor, ClientError) {
  let fields =
    [
      #("challenge_id", json.string(challenge_id)),
      #("credential", credential),
    ]
    |> list.append(optional_string_field("label", label))

  request_json(
    client,
    http.Post,
    "/auth/passkeys/registration/verify",
    Some(access_token),
    Some(json.object(fields)),
    model.factor_decoder(),
  )
}

pub fn start_passkey_authentication(
  client: Client,
  access_token: String,
) -> Result(CeremonyStart, ClientError) {
  request_json(
    client,
    http.Post,
    "/auth/passkeys/authentication/options",
    Some(access_token),
    Some(json.object([])),
    model.ceremony_start_decoder(),
  )
}

pub fn finish_passkey_authentication(
  client: Client,
  access_token: String,
  challenge_id: String,
  credential: json.Json,
) -> Result(StepUpResponse, ClientError) {
  request_json(
    client,
    http.Post,
    "/auth/passkeys/authentication/verify",
    Some(access_token),
    Some(
      json.object([
        #("challenge_id", json.string(challenge_id)),
        #("credential", credential),
      ]),
    ),
    model.step_up_response_decoder(),
  )
}

fn default_transport(
  req: Request(String),
  timeout_ms: Int,
) -> Result(Response(String), httpc.HttpError) {
  httpc.configure()
  |> httpc.timeout(timeout_ms)
  |> httpc.follow_redirects(False)
  |> httpc.dispatch(req)
}

fn request_json(
  client: Client,
  method: http.Method,
  path: String,
  bearer: Option(String),
  body: Option(json.Json),
  decoder: decode.Decoder(value),
) -> Result(value, ClientError) {
  use req <- result.try(build_request(client, method, path, bearer, body))
  use response <- result.try(send(client, req))
  decode_json_response(response, decoder)
}

fn request_empty(
  client: Client,
  method: http.Method,
  path: String,
  bearer: Option(String),
  body: Option(json.Json),
) -> Result(Nil, ClientError) {
  use req <- result.try(build_request(client, method, path, bearer, body))
  use response <- result.try(send(client, req))
  case response.status {
    401 -> Error(Unauthorized)
    status ->
      case is_success(status) {
        True -> Ok(Nil)
        False -> Error(UnexpectedStatus(status))
      }
  }
}

fn build_request(
  client: Client,
  method: http.Method,
  path: String,
  bearer: Option(String),
  body: Option(json.Json),
) -> Result(Request(String), ClientError) {
  case request.to(client.base <> path) {
    Error(_) -> Error(InvalidUrl)
    Ok(req) -> {
      let req =
        req
        |> request.set_method(method)
        |> request.set_header("accept", "application/json")

      let req = case bearer {
        Some(token) ->
          request.set_header(req, "authorization", "Bearer " <> token)
        None -> req
      }

      let req = case body {
        Some(value) ->
          req
          |> request.set_header("content-type", "application/json")
          |> request.set_body(json.to_string(value))
        None -> req
      }

      Ok(req)
    }
  }
}

fn send(
  client: Client,
  req: Request(String),
) -> Result(Response(String), ClientError) {
  client.transport(req, client.timeout_ms)
  |> result.map_error(TransportError)
}

fn decode_json_response(
  response: Response(String),
  decoder: decode.Decoder(value),
) -> Result(value, ClientError) {
  case response.status {
    401 -> Error(Unauthorized)
    status ->
      case is_success(status) {
        True ->
          response.body
          |> json.parse(decoder)
          |> result.map_error(InvalidResponse)
        False -> Error(UnexpectedStatus(status))
      }
  }
}

fn is_success(status: Int) -> Bool {
  status >= 200 && status < 300
}

fn normalize_base(base: String) -> String {
  base |> string.trim |> trim_trailing_slashes
}

fn trim_trailing_slashes(value: String) -> String {
  case string.ends_with(value, "/") {
    True -> value |> string.remove_suffix("/") |> trim_trailing_slashes
    False -> value
  }
}

fn optional_string_field(
  name: String,
  value: Option(String),
) -> List(#(String, json.Json)) {
  case value {
    Some(value) ->
      case value |> string.trim |> string.to_option {
        Some(value) -> [#(name, json.string(value))]
        None -> []
      }
    None -> []
  }
}
