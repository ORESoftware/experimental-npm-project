from pathlib import Path

path = Path(__file__).resolve().parent / "dart" / "test" / "introspection_service_credential_test.dart"
text = path.read_text()
old = """  test('protected introspection fails before transport when unconfigured', () async {
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
"""
new = """  test('protected introspection fails before transport when unconfigured', () {
    var calls = 0;
    final client = SharedAuthClient(
      'https://gateway.example/shared-auth',
      httpClient: MockClient((_) async {
        calls += 1;
        return http.Response('{}', 500);
      }),
    );

    expect(
      () => client.introspect('ore-token'),
      throwsA(isA<MissingServiceCredentialException>()),
    );
    expect(calls, 0);
  });
"""
if text.count(old) != 1:
    raise SystemExit("expected generated Dart test block was not found exactly once")
path.write_text(text.replace(old, new, 1))
