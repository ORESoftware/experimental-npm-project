from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parent


def concatenate(directory: Path, target_name: str) -> Path:
    parts = sorted(directory.glob(f"{target_name}.part*"))
    if not parts:
        raise SystemExit(f"no source parts found for {directory / target_name}")
    target = directory / target_name
    target.write_text("".join(part.read_text() for part in parts))
    for part in parts:
        part.unlink()
    return target


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(
            f"{path}: expected one replacement match, found {count}: {old[:100]!r}"
        )
    path.write_text(text.replace(old, new, 1))


# Rust: preserve the previously validated transport hardening and make protected
# introspection fail locally when its independent service credential is absent.
rust = concatenate(ROOT / "rust" / "src", "lib.rs")
replace_once(
    rust,
    '''    #[error("unauthorized")]
    Unauthorized,
    #[error("invalid shared-auth base URL")]''',
    '''    #[error("unauthorized")]
    Unauthorized,
    /// Protected introspection was called without the independent service
    /// credential. No HTTP request was attempted.
    #[error("introspection service credential is required")]
    MissingServiceCredential,
    #[error("invalid shared-auth base URL")]''',
)
replace_once(
    rust,
    '''    /// RFC-7662-shaped introspection of a shared-auth token.
    pub async fn introspect(&self, token: &str) -> Result<Introspection, ClientError> {
        let token = required_credential(token, "token")?;
        let request = self.request(Method::POST, &["auth", "introspect"])?;
        let request = self.with_json(request, &serde_json::json!({ "token": token }))?;
        let request = match &self.service_credential {
            Some(credential) => with_bearer(request, credential.as_ref(), "service credential")?,
            None => request,
        };
        self.send_json(request).await
    }
''',
    '''    /// RFC-7662-shaped protected introspection of a shared-auth token.
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
''',
)
rust_tests = ROOT / "rust" / "tests"
rust_tests.mkdir(parents=True, exist_ok=True)
(rust_tests / "introspection_service_credential.rs").write_text(
    '''use shared_auth_client::{ClientError, SharedAuthClient};

#[tokio::test]
async fn missing_service_credential_fails_before_transport() {
    let client = SharedAuthClient::new("http://127.0.0.1:1");
    let error = client.introspect("ore-token").await.unwrap_err();
    assert!(matches!(error, ClientError::MissingServiceCredential));
}

#[tokio::test]
async fn explicit_removal_restores_missing_credential_error() {
    let client = SharedAuthClient::new("http://127.0.0.1:1")
        .with_service_credential("service-secret")
        .without_service_credential();
    let error = client.introspect("ore-token").await.unwrap_err();
    assert!(matches!(error, ClientError::MissingServiceCredential));
}
'''
)

# TypeScript: preserve browser transport/body hardening and add a typed local
# configuration error for protected introspection.
ts = concatenate(ROOT / "ts" / "src", "index.ts")
replace_once(
    ts,
    '''export class UnauthorizedError extends Error {
  constructor() {
    super("unauthorized");
    this.name = "UnauthorizedError";
  }
}

export class SharedAuthHttpError extends Error {''',
    '''export class UnauthorizedError extends Error {
  constructor() {
    super("unauthorized");
    this.name = "UnauthorizedError";
  }
}

export class MissingServiceCredentialError extends Error {
  constructor() {
    super("introspection service credential is required");
    this.name = "MissingServiceCredentialError";
  }
}

export class SharedAuthHttpError extends Error {''',
)
replace_once(
    ts,
    '''  /** RFC-7662-shaped introspection, authenticated when a service credential is set. */
  async introspect(token: string): Promise<Introspection> {
    const headers: Record<string, string> = {
      "content-type": "application/json",
    };
    if (this.serviceCredential) {
      headers.authorization = `Bearer ${this.serviceCredential}`;
    }
    return this.requestJson<Introspection>("/auth/introspect", {
      method: "POST",
      headers,
      body: encodeJson({ token: requiredCredential(token, "token") }),
    });
  }
''',
    '''  /** Missing service credentials fail locally before fetch is called. */
  async introspect(token: string): Promise<Introspection> {
    const serviceCredential = this.serviceCredential;
    if (serviceCredential === undefined) {
      throw new MissingServiceCredentialError();
    }
    return this.requestJson<Introspection>("/auth/introspect", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${serviceCredential}`,
      },
      body: encodeJson({ token: requiredCredential(token, "token") }),
    });
  }
''',
)
ts_tests = ROOT / "ts" / "test"
ts_tests.mkdir(parents=True, exist_ok=True)
(ts_tests / "client.test.mjs").write_text(
    '''import assert from "node:assert/strict";
import test from "node:test";
import {
  MissingServiceCredentialError,
  SharedAuthClient,
} from "../dist/index.js";

test("protected introspection fails before fetch when unconfigured", async () => {
  let calls = 0;
  const client = new SharedAuthClient("https://gateway.example/shared-auth", {
    fetch: async () => {
      calls += 1;
      throw new Error("fetch must not be called");
    },
  });

  await assert.rejects(
    client.introspect("ore-token"),
    MissingServiceCredentialError,
  );
  assert.equal(calls, 0);

  client.withServiceCredential("service-secret").withoutServiceCredential();
  await assert.rejects(
    client.introspect("ore-token"),
    MissingServiceCredentialError,
  );
  assert.equal(calls, 0);
});

test("configured introspection sends only the service bearer", async () => {
  let authorization;
  const client = new SharedAuthClient("https://gateway.example/shared-auth", {
    serviceCredential: "service-secret",
    fetch: async (_url, init) => {
      authorization = new Headers(init.headers).get("authorization");
      return Response.json({ active: false });
    },
  });
  const result = await client.introspect("ore-token");
  assert.equal(result.active, false);
  assert.equal(authorization, "Bearer service-secret");
});
'''
)

# Dart: add the same typed local configuration failure while retaining the
# existing endpoint and bounded response behavior.
dart_client = concatenate(ROOT / "dart" / "lib" / "src", "client.dart")
dart_errors = ROOT / "dart" / "lib" / "src" / "errors.dart"
dart_errors.write_text(
    dart_errors.read_text()
    + '''

/// Protected introspection was called without its service credential.
final class MissingServiceCredentialException
    extends SharedAuthClientException {
  const MissingServiceCredentialException() : super('/auth/introspect');

  @override
  String toString() =>
      'SharedAuthClientException: introspection service credential is required';
}
'''
)
replace_once(
    dart_client,
    '''  Future<Introspection> introspect(String token) =>
      _requestJson<Introspection>(
        'POST',
        '/auth/introspect',
        bearer: _serviceCredential,
        body: <String, Object?>{'token': token},
        decode: Introspection.fromJson,
      );
''',
    '''  Future<Introspection> introspect(String token) {
    const path = '/auth/introspect';
    final serviceCredential = _serviceCredential;
    if (serviceCredential == null) {
      throw const MissingServiceCredentialException();
    }
    return _requestJson<Introspection>(
      'POST',
      path,
      bearer: serviceCredential,
      body: <String, Object?>{'token': token},
      decode: Introspection.fromJson,
    );
  }
''',
)
dart_tests = ROOT / "dart" / "test"
dart_tests.mkdir(parents=True, exist_ok=True)
(dart_tests / "introspection_service_credential_test.dart").write_text(
    '''import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:shared_auth_client/shared_auth_client.dart';
import 'package:test/test.dart';

void main() {
  test('protected introspection fails before transport when unconfigured', () async {
    var calls = 0;
    final client = SharedAuthClient(
      'https://gateway.example/shared-auth',
      httpClient: MockClient((_) async {
        calls += 1;
        return http.Response('{}', 500);
      }),
    );

    await expectLater(
      client.introspect('ore-token'),
      throwsA(isA<MissingServiceCredentialException>()),
    );
    expect(calls, 0);
  });

  test('configured introspection sends the service bearer', () async {
    String? authorization;
    final client = SharedAuthClient(
      'https://gateway.example/shared-auth',
      serviceCredential: 'service-secret',
      httpClient: MockClient((request) async {
        authorization = request.headers['authorization'];
        return http.Response('{"active":false}', 200);
      }),
    );

    final result = await client.introspect('ore-token');
    expect(result.active, isFalse);
    expect(authorization, 'Bearer service-secret');
  });
}
'''
)

# Gleam: return a local typed error without constructing or dispatching a
# request when the protected endpoint has not been configured.
gleam = concatenate(ROOT / "gleam" / "src", "shared_auth_client.gleam")
replace_once(
    gleam,
    '''pub type ClientError {
  Unauthorized
  UnexpectedStatus(status: Int)''',
    '''pub type ClientError {
  Unauthorized
  MissingServiceCredential
  UnexpectedStatus(status: Int)''',
)
replace_once(
    gleam,
    '''/// RFC-7662-shaped protected introspection.
pub fn introspect(
  client: Client,
  token: String,
) -> Result(Introspection, ClientError) {
  request_json(
    client,
    http.Post,
    "/auth/introspect",
    client.service_credential,
    Some(json.object([#("token", json.string(token))])),
    model.introspection_decoder(),
  )
}
''',
    '''/// RFC-7662-shaped protected introspection.
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
''',
)
gleam_tests = ROOT / "gleam" / "test"
gleam_tests.mkdir(parents=True, exist_ok=True)
(gleam_tests / "shared_auth_client_test.gleam").write_text(
    '''import gleeunit
import shared_auth_client

pub fn main() {
  gleeunit.main()
}

pub fn protected_introspection_requires_service_credential_test() {
  let assert Ok(client) =
    shared_auth_client.new("https://gateway.example/shared-auth")
  assert shared_auth_client.introspect(client, "ore-token")
    == Error(shared_auth_client.MissingServiceCredential)

  let client =
    client
    |> shared_auth_client.with_service_credential("service-secret")
    |> shared_auth_client.without_service_credential
  assert shared_auth_client.introspect(client, "ore-token")
    == Error(shared_auth_client.MissingServiceCredential)
}
'''
)
