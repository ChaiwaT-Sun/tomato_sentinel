// Copyright (c) 2026 Tomato Sentinel
// Central security management service

import 'dart:async';
import '../tomato_sentinel_config.dart';
import '../tomato_sentinel.dart';
import '../models/security_check_result.dart';
import '../models/security_threat.dart';
import '../platform/method_channel_tomato_sentinel.dart';

/// Coordinates all security checks and threat detection.
///
/// Bridges the Dart layer with native security implementations on Android
/// and iOS. Implements TOCTOU (Time-of-Check-Time-of-Use) prevention through
/// continuous background monitoring and cached results with a configurable TTL.
class SecurityManager {
  final TomatoSentinelConfig _config;
  final MethodChannelTomatoSentinel _platform;

  SecurityStatus? _cachedStatus;
  DateTime? _lastCheckTime;
  Timer? _periodicCheckTimer;

  SecurityManager(this._config)
      : _platform = MethodChannelTomatoSentinel() {
    _startPeriodicChecks();
  }

  /// Starts a recurring timer that re-runs all security checks at the interval
  /// defined by [TomatoSentinelConfig.integrityCheckInterval].
  /// This prevents TOCTOU attacks where a threat is introduced after the
  /// initial check passes.
  void _startPeriodicChecks() {
    if (_config.integrityCheckInterval.inSeconds > 0) {
      _periodicCheckTimer = Timer.periodic(
        _config.integrityCheckInterval,
        (_) => performSecurityChecks(),
      );
    }
  }

  /// Runs all enabled security checks and returns an aggregated [SecurityStatus].
  Future<SecurityStatus> performSecurityChecks() async {
    final results = <String, SecurityCheckResult>{};

    // Root / jailbreak detection.
    if (_config.enableRootDetection) {
      results['root'] = await _checkRoot();
    }

    // Emulator / simulator detection.
    if (_config.enableEmulatorDetection) {
      results['emulator'] = await _checkEmulator();
    }

    // Hooking framework detection (Frida, Xposed, Cydia Substrate).
    if (_config.enableHookDetection) {
      results['hook'] = await _checkHooks();
    }

    // Binary tamper detection.
    if (_config.enableTamperDetection) {
      results['tamper'] = await _checkTamper();
    }

    // Play Integrity / App Attest integrity check.
    if (_config.enableIntegrityCheck) {
      results['integrity'] = await _checkIntegrity();
    }

    final isSecure = results.values.every((r) => r.isSecure);

    _cachedStatus = SecurityStatus(
      isDeviceSecure: isSecure,
      checkResults: results,
      lastChecked: DateTime.now(),
    );
    _lastCheckTime = DateTime.now();

    // Fire security events for every detected threat.
    if (!isSecure) {
      for (final result in results.values) {
        for (final threat in result.threats) {
          _reportSecurityEvent(threat);
        }
      }
    }

    return _cachedStatus!;
  }

  /// Runs a single security check of the specified [type].
  Future<SecurityCheckResult> performSpecificCheck(
    SecurityCheckType type,
  ) async {
    switch (type) {
      case SecurityCheckType.rootDetection:
        return await _checkRoot();
      case SecurityCheckType.emulatorDetection:
        return await _checkEmulator();
      case SecurityCheckType.hookDetection:
        return await _checkHooks();
      case SecurityCheckType.tamperDetection:
        return await _checkTamper();
      case SecurityCheckType.integrityCheck:
        return await _checkIntegrity();
      case SecurityCheckType.all:
        final status = await performSecurityChecks();
        return SecurityCheckResult(
          isSecure: status.isDeviceSecure,
          threats: status.allThreats,
          checkedAt: status.lastChecked,
          checkType: 'all',
        );
    }
  }

  /// Checks whether the device is rooted (Android) or jailbroken (iOS).
  Future<SecurityCheckResult> _checkRoot() async {
    try {
      final result = await _platform.isDeviceRooted();

      if (result) {
        final threat = SecurityThreat.create(
          type: ThreatType.rootedDevice,
          severity: ThreatSeverity.critical,
          description: 'Device is rooted or jailbroken',
          details: {'timestamp': DateTime.now().toIso8601String()},
        );
        return SecurityCheckResult.insecure(
          checkType: 'root',
          threats: [threat],
        );
      }

      return SecurityCheckResult.secure('root');
    } catch (e) {
      return _handleCheckError('root', e);
    }
  }

  /// Checks whether the app is running inside an emulator or simulator.
  Future<SecurityCheckResult> _checkEmulator() async {
    try {
      final result = await _platform.isEmulator();

      if (result) {
        final threat = SecurityThreat.create(
          type: ThreatType.emulatorDetected,
          severity: ThreatSeverity.high,
          description: 'Running in emulator or simulator',
          details: {'timestamp': DateTime.now().toIso8601String()},
        );
        return SecurityCheckResult.insecure(
          checkType: 'emulator',
          threats: [threat],
        );
      }

      return SecurityCheckResult.secure('emulator');
    } catch (e) {
      return _handleCheckError('emulator', e);
    }
  }

  /// Checks for the presence of hooking frameworks such as Frida or Xposed.
  Future<SecurityCheckResult> _checkHooks() async {
    try {
      final result = await _platform.isHooked();

      if (result) {
        final threat = SecurityThreat.create(
          type: ThreatType.hookingFrameworkDetected,
          severity: ThreatSeverity.critical,
          description: 'Hooking framework detected (Frida, Xposed, etc.)',
          details: {'timestamp': DateTime.now().toIso8601String()},
        );
        return SecurityCheckResult.insecure(
          checkType: 'hook',
          threats: [threat],
        );
      }

      return SecurityCheckResult.secure('hook');
    } catch (e) {
      return _handleCheckError('hook', e);
    }
  }

  /// Checks whether the app binary has been tampered with.
  Future<SecurityCheckResult> _checkTamper() async {
    try {
      final result = await _platform.isTampered();

      if (result) {
        final threat = SecurityThreat.create(
          type: ThreatType.tamperingDetected,
          severity: ThreatSeverity.critical,
          description: 'App binary has been tampered with',
          details: {'timestamp': DateTime.now().toIso8601String()},
        );
        return SecurityCheckResult.insecure(
          checkType: 'tamper',
          threats: [threat],
        );
      }

      return SecurityCheckResult.secure('tamper');
    } catch (e) {
      return _handleCheckError('tamper', e);
    }
  }

  /// Verifies device integrity via Play Integrity API (Android) or
  /// App Attest (iOS).
  Future<SecurityCheckResult> _checkIntegrity() async {
    try {
      final result = await _platform.checkIntegrity();

      if (!result['isValid']) {
        final threat = SecurityThreat.create(
          type: ThreatType.integrityCheckFailed,
          severity: ThreatSeverity.high,
          description: 'Device integrity check failed',
          details: result,
        );
        return SecurityCheckResult.insecure(
          checkType: 'integrity',
          threats: [threat],
        );
      }

      return SecurityCheckResult.secure('integrity');
    } catch (e) {
      return _handleCheckError('integrity', e);
    }
  }

  /// Handles errors thrown by individual security checks.
  ///
  /// When [TomatoSentinelConfig.failClosed] is true, a check error is treated
  /// as a security failure (insecure). When false, the check is considered
  /// passed so the app can continue running (suitable for development only).
  SecurityCheckResult _handleCheckError(String checkType, Object error) {
    if (_config.failClosed) {
      final threat = SecurityThreat.create(
        type: ThreatType.unknown,
        severity: ThreatSeverity.high,
        description: 'Security check failed: $error',
        details: {'checkType': checkType, 'error': error.toString()},
      );
      return SecurityCheckResult.insecure(
        checkType: checkType,
        threats: [threat],
      );
    }
    return SecurityCheckResult.secure(checkType);
  }

  /// Converts a [SecurityThreat] into a [SecurityEvent] and dispatches it to
  /// both the config-level callback (logging) and the global UI callback
  /// (real-time alert dialog).
  void _reportSecurityEvent(SecurityThreat threat) {
    SecurityEventType eventType;
    switch (threat.type) {
      case ThreatType.rootedDevice:
        eventType = SecurityEventType.rootDetected;
        break;
      case ThreatType.emulatorDetected:
        eventType = SecurityEventType.emulatorDetected;
        break;
      case ThreatType.hookingFrameworkDetected:
        eventType = SecurityEventType.hookDetected;
        break;
      case ThreatType.tamperingDetected:
        eventType = SecurityEventType.tamperDetected;
        break;
      case ThreatType.integrityCheckFailed:
        eventType = SecurityEventType.integrityCheckFailed;
        break;
      default:
        eventType = SecurityEventType.securityCheckPassed;
    }

    final event = SecurityEvent(
      type: eventType,
      message: threat.description,
      metadata: threat.details,
    );

    // Dispatch to the config-level callback (e.g. debugPrint or a custom logger).
    _config.onSecurityEvent?.call(event);

    // Dispatch to the global UI callback wired from SecurityAlertNotifier.
    // This triggers the alert dialog without waiting for the next periodic check.
    globalSecurityEventCallback?.call(event);
  }

  /// Returns the cached [SecurityStatus] if it is still within the TTL defined
  /// by [TomatoSentinelConfig.integrityCheckInterval].
  ///
  /// Returns null if the cache is empty or has expired, signalling that a fresh
  /// check should be performed.
  SecurityStatus? getCachedStatus() {
    if (_cachedStatus == null || _lastCheckTime == null) {
      return null;
    }

    final age = DateTime.now().difference(_lastCheckTime!);
    if (age > _config.integrityCheckInterval) {
      return null; // Cache expired — caller should run a fresh check.
    }

    return _cachedStatus;
  }

  /// Cancels the periodic check timer and releases resources.
  void dispose() {
    _periodicCheckTimer?.cancel();
    _periodicCheckTimer = null;
  }
}
