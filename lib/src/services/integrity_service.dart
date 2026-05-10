// Copyright (c) 2026 Tomato Sentinel
// Device integrity verification service

import 'dart:io';
import '../tomato_sentinel_config.dart';
import '../models/integrity_result.dart';
import '../platform/method_channel_tomato_sentinel.dart';
import '../exceptions/security_exceptions.dart';

/// Integrity Service
/// 
/// Manages Play Integrity API (Android) and App Attest (iOS) integration.
/// Provides device and app integrity verification.
class IntegrityService {
  final TomatoSentinelConfig _config;
  final MethodChannelTomatoSentinel _platform;
  
  DateTime? _lastCheckTime;
  IntegrityResult? _cachedResult;

  IntegrityService(this._config) : _platform = MethodChannelTomatoSentinel();

  /// Initialize integrity service
  Future<void> initialize() async {
    if (Platform.isAndroid) {
      await _initializePlayIntegrity();
    } else if (Platform.isIOS) {
      await _initializeAppAttest();
    }
  }

  /// Initialize Play Integrity API (Android)
  Future<void> _initializePlayIntegrity() async {
    if (_config.playIntegrityCloudProjectNumber == null) {
      throw SecurityException(
        'Play Integrity cloud project number not configured',
      );
    }

    try {
      await _platform.initializePlayIntegrity(
        _config.playIntegrityCloudProjectNumber!,
      );
    } catch (e) {
      throw SecurityException('Failed to initialize Play Integrity: $e');
    }
  }

  /// Initialize App Attest (iOS)
  Future<void> _initializeAppAttest() async {
    if (_config.appAttestKeyId == null) {
      throw SecurityException('App Attest key ID not configured');
    }

    try {
      await _platform.initializeAppAttest(_config.appAttestKeyId!);
    } catch (e) {
      throw SecurityException('Failed to initialize App Attest: $e');
    }
  }

  /// Check device integrity
  Future<IntegrityResult> checkIntegrity({bool forceRefresh = false}) async {
    // Return cached result if available and not expired
    if (!forceRefresh && _cachedResult != null && _lastCheckTime != null) {
      final age = DateTime.now().difference(_lastCheckTime!);
      if (age < _config.integrityCheckInterval) {
        return _cachedResult!;
      }
    }

    try {
      final result = await _platform.checkIntegrity();
      
      IntegrityResult integrityResult;
      if (Platform.isAndroid) {
        integrityResult = PlayIntegrityResult.fromNative(result);
      } else if (Platform.isIOS) {
        integrityResult = AppAttestResult.fromNative(result);
      } else {
        integrityResult = IntegrityResult.invalid(
          verdict: IntegrityVerdict.unavailable,
          details: {'platform': 'unsupported'},
        );
      }

      _cachedResult = integrityResult;
      _lastCheckTime = DateTime.now();

      return integrityResult;
    } catch (e) {
      throw SecurityException('Integrity check failed: $e');
    }
  }

  /// Get cached integrity result
  IntegrityResult? get cachedResult => _cachedResult;

  /// Clear cached result
  void clearCache() {
    _cachedResult = null;
    _lastCheckTime = null;
  }
}
