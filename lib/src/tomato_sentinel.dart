// Copyright (c) 2026 Tomato Sentinel
// Main SDK entry point

import 'dart:async';
import 'package:flutter/foundation.dart';
import 'tomato_sentinel_config.dart';
import 'models/security_check_result.dart';
import 'services/security_manager.dart';
import 'services/remote_config_service.dart';
import 'exceptions/security_exceptions.dart';

/// Main Tomato Sentinel SDK class
/// 
/// Usage:
/// ```dart
/// final config = TomatoSentinelConfig.production(...);
/// await TomatoSentinel.initialize(config);
/// 
/// final status = await TomatoSentinel.instance.getSecurityStatus();
/// if (!status.isDeviceSecure) {
///   // Handle security threat
/// }
/// ```
class TomatoSentinel {
  static TomatoSentinel? _instance;
  static TomatoSentinelConfig? _config;

  final SecurityManager _securityManager;
  final RemoteConfigService _remoteConfigService;

  TomatoSentinel._({
    required SecurityManager securityManager,
    required RemoteConfigService remoteConfigService,
  })  : _securityManager = securityManager,
        _remoteConfigService = remoteConfigService;

  /// Get singleton instance
  /// Throws [SecurityException] if not initialized
  static TomatoSentinel get instance {
    if (_instance == null) {
      throw SecurityException(
        'TomatoSentinel not initialized. Call TomatoSentinel.initialize() first.',
      );
    }
    return _instance!;
  }

  /// Check if SDK is initialized
  static bool get isInitialized => _instance != null;

  /// Get current configuration
  static TomatoSentinelConfig? get config => _config;

  /// Initialize the SDK
  /// 
  /// MUST be called before using any other SDK features.
  /// Performs initial security checks and sets up monitoring.
  /// 
  /// Throws [SecurityException] if critical security checks fail
  /// and [TomatoSentinelConfig.failClosed] is true.
  static Future<void> initialize(TomatoSentinelConfig config) async {
    if (_instance != null) {
      debugPrint('TomatoSentinel already initialized');
      return;
    }

    _config = config;

    // Check if we should enforce security in current build mode
    final shouldEnforce = kReleaseMode || config.enforceInDebugMode;

    final securityManager = SecurityManager(config);
    final remoteConfigService = RemoteConfigService(config);

    _instance = TomatoSentinel._(
      securityManager: securityManager,
      remoteConfigService: remoteConfigService,
    );

    try {
      // Perform initial security checks
      await _instance!._performInitialSecurityChecks(shouldEnforce);

      // Fetch remote configuration if configured
      if (config.remoteConfigUrl != null) {
        await _instance!._remoteConfigService.fetchAndApplyConfig();
      }

      debugPrint('TomatoSentinel initialized successfully');
    } catch (e) {
      if (config.failClosed && shouldEnforce) {
        _instance = null;
        _config = null;
        rethrow;
      } else {
        debugPrint('TomatoSentinel initialization warning: $e');
      }
    }
  }

  /// Perform initial security checks
  Future<void> _performInitialSecurityChecks(bool shouldEnforce) async {
    final result = await _securityManager.performSecurityChecks();

    if (!result.isDeviceSecure) {
      final event = SecurityEvent(
        type: SecurityEventType.securityCheckPassed,
        message: 'Initial security check failed',
        metadata: {
          'threats': result.allThreats.map((t) => t.toString()).toList(),
        },
      );
      _config?.onSecurityEvent?.call(event);

      if (shouldEnforce && _config!.failClosed && result.hasCriticalThreats) {
        throw SecurityException(
          'Critical security threats detected: ${result.allThreats.map((t) => t.type).join(", ")}',
        );
      }
    }
  }

  /// Get current security status
  Future<SecurityStatus> getSecurityStatus() async {
    return await _securityManager.performSecurityChecks();
  }

  /// Perform a specific security check
  Future<SecurityCheckResult> performCheck(SecurityCheckType type) async {
    return await _securityManager.performSpecificCheck(type);
  }

  /// Check if device is rooted/jailbroken
  Future<bool> isDeviceRooted() async {
    final result = await performCheck(SecurityCheckType.rootDetection);
    return !result.isSecure;
  }

  /// Check if running in emulator
  Future<bool> isEmulator() async {
    final result = await performCheck(SecurityCheckType.emulatorDetection);
    return !result.isSecure;
  }

  /// Check if hooking frameworks are detected
  Future<bool> isHooked() async {
    final result = await performCheck(SecurityCheckType.hookDetection);
    return !result.isSecure;
  }

  /// Check if app has been tampered with
  Future<bool> isTampered() async {
    final result = await performCheck(SecurityCheckType.tamperDetection);
    return !result.isSecure;
  }

  /// Verify device integrity (Play Integrity / App Attest)
  Future<SecurityCheckResult> verifyIntegrity() async {
    return await performCheck(SecurityCheckType.integrityCheck);
  }

  /// Update configuration from remote source
  Future<void> updateRemoteConfig() async {
    if (_config?.remoteConfigUrl == null) {
      throw SecurityException('Remote config URL not configured');
    }
    await _remoteConfigService.fetchAndApplyConfig();
  }

  /// Dispose resources
  static Future<void> dispose() async {
    _instance?._securityManager.dispose();
    _instance = null;
    _config = null;
  }

  /// Reset SDK (for testing purposes only)
  @visibleForTesting
  static void reset() {
    _instance = null;
    _config = null;
  }
}

/// Security check types
enum SecurityCheckType {
  rootDetection,
  emulatorDetection,
  hookDetection,
  tamperDetection,
  integrityCheck,
  all,
}
