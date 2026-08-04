import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:http/http.dart' as http;

import 'errors.dart';
import 'models.dart';

/// A bounded, redirect-free HTTP client for the shared-auth API.
final class SharedAuthClient {
  SharedAuthClient(
    String baseUrl, {
    http.Client? httpClient,
    Duration timeout = const Duration(seconds: 10),
    int maximumResponseBytes = 1024 * 1024,
    String? serviceCredential,
  })  : _baseUrl = _normalizeBaseUrl(baseUrl),
        _http = httpClient ?? http.Client(),
        _ownsHttpClient = httpClient == null,
        _timeout = _positiveDuration(timeout),
        _maximumResponseBytes = _positiveMaximum(maximumResponseBytes),
        _serviceCredential = _nonEmpty(serviceCredential);

  final String _baseUrl;
  final http.Client _http;
  final bool _ownsHttpClient;
  final Duration _timeout;
  final int _maximumResponseBytes;
  String? _serviceCredential;

  /// Configure the service bearer used only for protected introspection.
  SharedAuthClient withServiceCredential(String credential) {
    _serviceCredential = _nonEmpty(credential);
    return this;
  }

  SharedAuthClient withoutServiceCredential() {
    _serviceCredential = null;
    return this;
  }

  void close() {
    if (_ownsHttpClient) {
      _http.close();
    }
  }

  Future<ExchangeResponse> exchange(String supabaseToken) =>
      _requestJson<ExchangeResponse>(
        'POST',
        '/auth/exchange',
        bearer: supabaseToken,
        decode: ExchangeResponse.fromJson,
      );

  Future<Introspection> introspect(String token) {
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

  Future<bool> verify(String token) async {
    const path = '/auth/verify';
    final response = await _request('GET', path, bearer: token);
    switch (response.statusCode) {
      case 200:
        return true;
      case 401:
        return false;
      default:
        throw SharedAuthStatusException(path, response.statusCode);
    }
  }

  Future<Jwks> jwks() => _requestJson<Jwks>(
        'GET',
        '/.well-known/jwks.json',
        decode: Jwks.fromJson,
      );

  Future<Capabilities> capabilities() => _requestJson<Capabilities>(
        'GET',
        '/auth/capabilities',
        decode: Capabilities.fromJson,
      );

  Future<List<Factor>> factors(String accessToken) async {
    const path = '/auth/factors';
    final json = await _requestJsonValue('GET', path, bearer: accessToken);
    if (json is! List<Object?>) {
      throw const SharedAuthDecodeException(
        path,
        FormatException('expected an array'),
      );
    }
    try {
      return List<Factor>.unmodifiable(
        json.map((Object? item) => Factor.fromJson(_asObject(item))),
      );
    } on SharedAuthClientException {
      rethrow;
    } on Object catch (error) {
      throw SharedAuthDecodeException(path, error);
    }
  }

  Future<TotpEnrollment> enrollTotp(
    String accessToken, {
    String? label,
  }) =>
      _requestJson<TotpEnrollment>(
        'POST',
        '/auth/factors/totp/enroll',
        bearer: accessToken,
        body: <String, Object?>{
          if (label != null && label.trim().isNotEmpty) 'label': label.trim(),
        },
        decode: TotpEnrollment.fromJson,
      );

  Future<StepUpResponse> confirmTotp(
    String accessToken, {
    required String factorId,
    required String code,
  }) =>
      _requestJson<StepUpResponse>(
        'POST',
        '/auth/factors/totp/confirm',
        bearer: accessToken,
        body: <String, Object?>{'factor_id': factorId, 'code': code},
        decode: StepUpResponse.fromJson,
      );

  Future<void> deleteFactor(String accessToken, String factorId) async {
    final path = '/auth/factors/${Uri.encodeComponent(factorId)}';
    final response = await _request('DELETE', path, bearer: accessToken);
    _requireSuccess(path, response.statusCode);
  }

  Future<ChallengeStart> createChallenge(
    String accessToken,
    ChallengeKind kind,
  ) =>
      _requestJson<ChallengeStart>(
        'POST',
        '/auth/challenges',
        bearer: accessToken,
        body: <String, Object?>{'kind': kind.wireValue},
        decode: ChallengeStart.fromJson,
      );

  Future<StepUpResponse> verifyChallenge(
    String accessToken, {
    required String challengeId,
    required String code,
  }) {
    final path = '/auth/challenges/${Uri.encodeComponent(challengeId)}/verify';
    return _requestJson<StepUpResponse>(
      'POST',
      path,
      bearer: accessToken,
      body: <String, Object?>{'code': code},
      decode: StepUpResponse.fromJson,
    );
  }

  Future<CeremonyStart> startPasskeyRegistration(
    String accessToken, {
    String? label,
  }) =>
      _requestJson<CeremonyStart>(
        'POST',
        '/auth/passkeys/registration/options',
        bearer: accessToken,
        body: <String, Object?>{
          if (label != null && label.trim().isNotEmpty) 'label': label.trim(),
        },
        decode: CeremonyStart.fromJson,
      );

  Future<Factor> finishPasskeyRegistration(
    String accessToken, {
    required String challengeId,
    required Object credential,
    String? label,
  }) =>
      _requestJson<Factor>(
        'POST',
        '/auth/passkeys/registration/verify',
        bearer: accessToken,
        body: <String, Object?>{
          'challenge_id': challengeId,
          'credential': credential,
          if (label != null && label.trim().isNotEmpty) 'label': label.trim(),
        },
        decode: Factor.fromJson,
      );

  Future<CeremonyStart> startPasskeyAuthentication(String accessToken) =>
      _requestJson<CeremonyStart>(
        'POST',
        '/auth/passkeys/authentication/options',
        bearer: accessToken,
        body: const <String, Object?>{},
        decode: CeremonyStart.fromJson,
      );

  Future<StepUpResponse> finishPasskeyAuthentication(
    String accessToken, {
    required String challengeId,
    required Object credential,
  }) =>
      _requestJson<StepUpResponse>(
        'POST',
        '/auth/passkeys/authentication/verify',
        bearer: accessToken,
        body: <String, Object?>{
          'challenge_id': challengeId,
          'credential': credential,
        },
        decode: StepUpResponse.fromJson,
      );
  Future<T> _requestJson<T>(
    String method,
    String path, {
    String? bearer,
    JsonObject? body,
    required T Function(JsonObject json) decode,
  }) async {
    final value = await _requestJsonValue(
      method,
      path,
      bearer: bearer,
      body: body,
    );
    try {
      return decode(_asObject(value));
    } on SharedAuthClientException {
      rethrow;
    } on Object catch (error) {
      throw SharedAuthDecodeException(path, error);
    }
  }

  Future<Object?> _requestJsonValue(
    String method,
    String path, {
    String? bearer,
    JsonObject? body,
  }) async {
    final response = await _request(
      method,
      path,
      bearer: bearer,
      body: body,
    );
    _requireSuccess(path, response.statusCode);
    try {
      return jsonDecode(response.body);
    } on Object catch (error) {
      throw SharedAuthDecodeException(path, error);
    }
  }

  Future<_WireResponse> _request(
    String method,
    String path, {
    String? bearer,
    JsonObject? body,
  }) async {
    final request = http.Request(method, Uri.parse('$_baseUrl$path'))
      ..followRedirects = false
      ..maxRedirects = 0
      ..headers['accept'] = 'application/json';

    final token = _nonEmpty(bearer);
    if (token != null) {
      request.headers['authorization'] = 'Bearer $token';
    }
    if (body != null) {
      request.headers['content-type'] = 'application/json';
      try {
        request.body = jsonEncode(body);
      } on Object catch (error) {
        throw ArgumentError.value(
          error,
          'body',
          'shared-auth request bodies must be JSON encodable',
        );
      }
    }

    try {
      return await (() async {
        final streamed = await _http.send(request);
        final responseBody = await _readBody(path, streamed.stream);
        return _WireResponse(streamed.statusCode, responseBody);
      })()
          .timeout(_timeout);
    } on SharedAuthClientException {
      rethrow;
    } on Object catch (error) {
      throw SharedAuthTransportException(path, error);
    }
  }

  Future<String> _readBody(
    String path,
    Stream<List<int>> stream,
  ) async {
    final bytes = BytesBuilder(copy: false);
    await for (final chunk in stream) {
      if (bytes.length + chunk.length > _maximumResponseBytes) {
        throw SharedAuthResponseTooLargeException(
          path,
          _maximumResponseBytes,
        );
      }
      bytes.add(chunk);
    }
    try {
      return utf8.decode(bytes.takeBytes(), allowMalformed: false);
    } on Object catch (error) {
      throw SharedAuthDecodeException(path, error);
    }
  }

  static void _requireSuccess(String path, int statusCode) {
    if (statusCode == 401) {
      throw UnauthorizedException(path);
    }
    if (statusCode < 200 || statusCode >= 300) {
      throw SharedAuthStatusException(path, statusCode);
    }
  }
}

final class _WireResponse {
  const _WireResponse(this.statusCode, this.body);

  final int statusCode;
  final String body;
}

String _normalizeBaseUrl(String input) {
  final value = input.trim();
  final uri = Uri.tryParse(value);
  if (uri == null ||
      !uri.hasScheme ||
      (uri.scheme != 'http' && uri.scheme != 'https') ||
      uri.host.isEmpty ||
      uri.hasQuery ||
      uri.hasFragment ||
      uri.userInfo.isNotEmpty) {
    throw ArgumentError.value(input, 'baseUrl', 'expected an HTTP(S) base URL');
  }
  final normalizedPath = uri.path.replaceFirst(RegExp(r'/+$'), '');
  return uri.replace(path: normalizedPath).toString();
}

Duration _positiveDuration(Duration timeout) {
  if (timeout <= Duration.zero) {
    throw ArgumentError.value(timeout, 'timeout', 'must be positive');
  }
  return timeout;
}

int _positiveMaximum(int maximum) {
  if (maximum <= 0) {
    throw ArgumentError.value(
      maximum,
      'maximumResponseBytes',
      'must be positive',
    );
  }
  return maximum;
}

String? _nonEmpty(String? value) {
  final normalized = value?.trim();
  return normalized == null || normalized.isEmpty ? null : normalized;
}

JsonObject _asObject(Object? value) {
  if (value is! Map<Object?, Object?>) {
    throw const FormatException('expected an object');
  }
  return value.map(
    (Object? key, Object? value) =>
        MapEntry<String, Object?>(key as String, value),
  );
}
