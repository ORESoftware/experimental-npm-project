import gleeunit
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
