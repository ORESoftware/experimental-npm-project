import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:shared_auth_client/shared_auth_client.dart';
import 'package:test/test.dart';

void main() {
  test('protected introspection fails before transport when unconfigured', () {
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
