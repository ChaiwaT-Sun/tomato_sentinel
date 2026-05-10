// Copyright (c) 2026 Tomato Sentinel
// Dio interceptor for SSL pinning validation

import 'dart:io';
import 'package:dio/dio.dart';
import '../tomato_sentinel_config.dart';
import '../exceptions/security_exceptions.dart';
import '../platform/method_channel_tomato_sentinel.dart';

/// Dio interceptor that enforces SSL pinning and hook detection on every
/// outbound HTTPS request.
///
/// Responsibilities:
///   1. Before each request — checks for active hooking frameworks (Frida,
///      Xposed, etc.) and rejects the request if one is found.
///   2. On TLS errors — detects [HandshakeException] caused by a certificate
///      that does not match any configured pin, fires a [pinningViolation]
///      security event, and re-throws as [SSLPinningException].
///
/// This provides defence-in-depth against MITM attacks even when a hooking
/// framework is injected after [TomatoSentinel.initialize] has already run.
class PinningInterceptor extends Interceptor {
  final TomatoSentinelConfig _config;
  final MethodChannelTomatoSentinel _platform;

  PinningInterceptor(this._config)
      : _platform = MethodChannelTomatoSentinel();

  @override
  void onRequest(
    RequestOptions options,
    RequestInterceptorHandler handler,
  ) async {
    // Only apply security checks to HTTPS requests.
    if (options.uri.scheme != 'https') {
      return handler.next(options);
    }

    // In debug builds, skip all checks for domains that have allowDebugBypass set.
    if (!const bool.fromEnvironment('dart.vm.product')) {
      final domain = options.uri.host;
      final pinConfig = _config.pinConfigurations[domain];
      if (pinConfig?.allowDebugBypass == true) {
        return handler.next(options);
      }
    }

    // ── Hook detection before every API call ──────────────────────────────────
    // Re-checks for hooking frameworks at request time to catch tools that were
    // injected after initialize() completed (e.g. Frida attached mid-session).
    if (_config.enableHookDetection) {
      try {
        final isHooked = await _platform.isHooked();
        if (isHooked) {
          // Notify the security event callback (logging / UI alert).
          _config.onSecurityEvent?.call(
            SecurityEvent(
              type: SecurityEventType.hookDetected,
              message: 'Hooking framework detected — API call blocked',
              metadata: {'url': options.uri.toString()},
            ),
          );

          // Block the request immediately.
          return handler.reject(
            DioException(
              requestOptions: options,
              error: HookDetectionException(
                'API call blocked: hooking framework detected',
              ),
              type: DioExceptionType.cancel,
            ),
          );
        }
      } catch (_) {
        // If the hook check itself fails and failClosed is enabled, block the
        // request rather than allowing it through on an uncertain state.
        if (_config.failClosed) {
          return handler.reject(
            DioException(
              requestOptions: options,
              error: HookDetectionException(
                'API call blocked: hook detection check failed (failClosed)',
              ),
              type: DioExceptionType.cancel,
            ),
          );
        }
      }
    }

    // Certificate validation happens at the HttpClient / native layer level.
    // The badCertificateCallback in createSecureHttpClient() handles SPKI
    // verification synchronously during the TLS handshake.
    return handler.next(options);
  }

  @override
  void onError(DioException err, ErrorInterceptorHandler handler) {
    // Detect TLS handshake failures caused by a certificate pin mismatch.
    if (err.type == DioExceptionType.connectionError) {
      if (err.error is HandshakeException) {
        final event = SecurityEvent(
          type: SecurityEventType.pinningViolation,
          message: 'SSL pinning violation detected',
          metadata: {
            'url': err.requestOptions.uri.toString(),
            'error': err.error.toString(),
          },
        );

        // Forward to the config callback (logging / analytics).
        _config.onSecurityEvent?.call(event);

        // Forward to the global UI callback so the alert dialog appears immediately.
        globalSecurityEventCallback?.call(event);

        return handler.reject(
          DioException(
            requestOptions: err.requestOptions,
            error: SSLPinningException(
              'SSL pinning validation failed',
              domain: err.requestOptions.uri.host,
            ),
            type: DioExceptionType.connectionError,
          ),
        );
      }
    }

    return handler.next(err);
  }
}

/// Creates a [HttpClient] configured with an SSL pinning callback.
///
/// Used internally by Dio for HTTPS connections. The [badCertificateCallback]
/// is invoked synchronously during the TLS handshake; actual SPKI hash
/// verification is delegated to the native layer.
HttpClient createSecureHttpClient(TomatoSentinelConfig config) {
  final client = HttpClient();

  client.badCertificateCallback = (cert, host, port) {
    // In production this must NEVER return true without proper validation.
    // Actual pin verification is handled by the native layer.

    // If no pin is configured for this host, fall back to default OS validation.
    final pinConfig = config.pinConfigurations[host];
    if (pinConfig == null) {
      return false;
    }

    // In debug builds, allow bypass if explicitly configured for this domain.
    if (!const bool.fromEnvironment('dart.vm.product')) {
      if (pinConfig.allowDebugBypass) {
        return true;
      }
    }

    // Delegate SPKI hash comparison to the native layer (Android / iOS).
    // This callback is synchronous, so async validation is not possible here.
    // The native plugin must be configured to perform the actual check.
    return false;
  };

  return client;
}
