// Copyright (c) 2026 Tomato Sentinel
// Riverpod providers for security state management

import 'dart:async';
import 'package:riverpod/riverpod.dart';
import '../tomato_sentinel.dart';
import '../tomato_sentinel_config.dart';
import '../models/security_check_result.dart';
import '../network/secure_dio_client.dart';

/// Provider for TomatoSentinel configuration.
final tomatoSentinelConfigProvider = Provider<TomatoSentinelConfig>((ref) {
  final config = TomatoSentinel.config;
  if (config == null) {
    throw Exception('TomatoSentinel not initialized');
  }
  return config;
});

/// Provider for the TomatoSentinel singleton instance.
final tomatoSentinelProvider = Provider<TomatoSentinel>((ref) {
  return TomatoSentinel.instance;
});

/// Provider for the current security status.
final securityStatusProvider = FutureProvider<SecurityStatus>((ref) async {
  final sentinel = ref.watch(tomatoSentinelProvider);
  return await sentinel.getSecurityStatus();
});

/// Provider for the root detection check result.
final rootDetectionProvider = FutureProvider<bool>((ref) async {
  final sentinel = ref.watch(tomatoSentinelProvider);
  return await sentinel.isDeviceRooted();
});

/// Provider for the emulator detection check result.
final emulatorDetectionProvider = FutureProvider<bool>((ref) async {
  final sentinel = ref.watch(tomatoSentinelProvider);
  return await sentinel.isEmulator();
});

/// Provider for the hook detection check result.
final hookDetectionProvider = FutureProvider<bool>((ref) async {
  final sentinel = ref.watch(tomatoSentinelProvider);
  return await sentinel.isHooked();
});

/// Provider for the tamper detection check result.
final tamperDetectionProvider = FutureProvider<bool>((ref) async {
  final sentinel = ref.watch(tomatoSentinelProvider);
  return await sentinel.isTampered();
});

/// Provider for the device integrity check result.
final integrityCheckProvider = FutureProvider<SecurityCheckResult>((ref) async {
  final sentinel = ref.watch(tomatoSentinelProvider);
  return await sentinel.verifyIntegrity();
});

/// Provider for a pre-configured secure Dio HTTP client.
final secureDioClientProvider = Provider<SecureDioClient>((ref) {
  final config = ref.watch(tomatoSentinelConfigProvider);
  return SecureDioClient.create(config);
});

/// Provider that exposes device security as a simple boolean.
final isDeviceSecureProvider = FutureProvider<bool>((ref) async {
  final status = await ref.watch(securityStatusProvider.future);
  return status.isDeviceSecure;
});

/// Stream provider for continuous real-time security monitoring.
///
/// Yields an initial [SecurityStatus] immediately, then re-checks on every
/// tick of [TomatoSentinelConfig.integrityCheckInterval].
final securityMonitoringProvider = StreamProvider<SecurityStatus>((ref) async* {
  final sentinel = ref.watch(tomatoSentinelProvider);

  // Emit the initial check result right away.
  yield await sentinel.getSecurityStatus();

  // Re-emit on every periodic interval defined in the config.
  final config = ref.watch(tomatoSentinelConfigProvider);
  await for (final _ in Stream.periodic(config.integrityCheckInterval)) {
    yield await sentinel.getSecurityStatus();
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// Real-time Security Alert System
// ─────────────────────────────────────────────────────────────────────────────

/// Data class representing a single security alert to display in the UI.
class SecurityAlert {
  final SecurityEventType type;
  final String title;
  final String message;
  final DateTime timestamp;

  /// When true the alert dialog cannot be dismissed by tapping outside —
  /// the user must explicitly tap the acknowledge button.
  final bool isCritical;

  const SecurityAlert({
    required this.type,
    required this.title,
    required this.message,
    required this.timestamp,
    required this.isCritical,
  });
}

/// Notifier that receives [SecurityEvent]s from the SDK and pushes them as a
/// broadcast stream so the UI can show a dialog immediately.
///
/// State holds the full alert history (useful for an audit log screen).
/// The [alertStream] carries only new alerts as they arrive.
class SecurityAlertNotifier extends StateNotifier<List<SecurityAlert>> {
  final StreamController<SecurityAlert> _alertStream =
      StreamController<SecurityAlert>.broadcast();

  SecurityAlertNotifier() : super([]);

  /// Stream of new alerts. UI widgets listen here to show dialogs in real time.
  Stream<SecurityAlert> get alertStream => _alertStream.stream;

  /// Called by the SDK's onSecurityEvent callback when a threat is detected.
  void onSecurityEvent(SecurityEvent event) {
    // Only build an alert for event types that require user notification.
    final alert = _buildAlert(event);
    if (alert == null) return;

    // Append to the history state.
    state = [...state, alert];

    // Push to the stream so the UI can react immediately.
    _alertStream.add(alert);
  }

  SecurityAlert? _buildAlert(SecurityEvent event) {
    switch (event.type) {
      case SecurityEventType.pinningViolation:
        return SecurityAlert(
          type: event.type,
          title: '⚠️ Connection Intercepted',
          message: 'A proxy or MITM attack was detected.\n'
              'The connection to the server has been blocked.\n\n'
              'URL: ${event.metadata?['url'] ?? '-'}',
          timestamp: event.timestamp,
          isCritical: true,
        );
      case SecurityEventType.hookDetected:
        return SecurityAlert(
          type: event.type,
          title: '🚨 Hooking Framework Detected',
          message: 'Frida, Xposed, or Cydia Substrate was found.\n'
              'API calls have been blocked for your security.',
          timestamp: event.timestamp,
          isCritical: true,
        );
      case SecurityEventType.rootDetected:
      case SecurityEventType.jailbreakDetected:
        return SecurityAlert(
          type: event.type,
          title: '🚨 Device is Rooted / Jailbroken',
          message: 'This device is not safe for use with this application.\n'
              'Please use a device that has not been rooted.',
          timestamp: event.timestamp,
          isCritical: true,
        );
      case SecurityEventType.tamperDetected:
        return SecurityAlert(
          type: event.type,
          title: '🚨 App Tampering Detected',
          message: 'A modification to the app binary was detected.\n'
              'Please reinstall the app from the official store.',
          timestamp: event.timestamp,
          isCritical: true,
        );
      case SecurityEventType.emulatorDetected:
        return SecurityAlert(
          type: event.type,
          title: '⚠️ Emulator Detected',
          message: 'The app is running on an emulator or simulator.\n'
              'Some features may be restricted.',
          timestamp: event.timestamp,
          isCritical: false,
        );
      case SecurityEventType.integrityCheckFailed:
        return SecurityAlert(
          type: event.type,
          title: '⚠️ Integrity Check Failed',
          message: 'Device integrity could not be verified.\n'
              '${event.message}',
          timestamp: event.timestamp,
          isCritical: false,
        );
      // Events that do not require a UI alert.
      case SecurityEventType.remoteConfigUpdateSuccess:
      case SecurityEventType.remoteConfigUpdateFailed:
      case SecurityEventType.securityCheckPassed:
        return null;
    }
  }

  /// Clears the full alert history.
  void clearAlerts() => state = [];

  @override
  void dispose() {
    _alertStream.close();
    super.dispose();
  }
}

/// Provider for [SecurityAlertNotifier].
final securityAlertProvider =
    StateNotifierProvider<SecurityAlertNotifier, List<SecurityAlert>>(
  (ref) => SecurityAlertNotifier(),
);
