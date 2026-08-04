use shared_auth_client::{ClientError, SharedAuthClient};

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
