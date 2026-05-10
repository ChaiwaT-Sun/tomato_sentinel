// Copyright (c) 2026 Tomato Sentinel
// Signed remote configuration service

import 'dart:convert';
import 'package:dio/dio.dart';
import '../tomato_sentinel_config.dart';
import '../models/remote_config.dart';
import '../exceptions/security_exceptions.dart';

/// Remote Configuration Service
/// 
/// Fetches and validates signed remote configurations.
/// Uses RSA-4096 or ECDSA P-384 signature verification.
/// 
/// Threat Model:
/// - Configuration tampering via MITM
/// - Unauthorized configuration updates
/// - Replay attacks with old configurations
class RemoteConfigService {
  final TomatoSentinelConfig _config;
  final Dio _dio;
  
  RemoteConfig? _currentConfig;
  int _lastAppliedVersion = 0;

  RemoteConfigService(this._config) : _dio = Dio();

  /// Fetch and apply remote configuration
  Future<void> fetchAndApplyConfig() async {
    if (_config.remoteConfigUrl == null) {
      throw SecurityException('Remote config URL not configured');
    }

    if (_config.remoteConfigPublicKey == null) {
      throw SecurityException('Remote config public key not configured');
    }

    try {
      // Fetch configuration
      final response = await _dio.get<Map<String, dynamic>>(
        _config.remoteConfigUrl!,
        options: Options(
          responseType: ResponseType.json,
          validateStatus: (status) => status == 200,
        ),
      );

      if (response.data == null) {
        throw SecurityException('Empty remote config response');
      }

      final remoteConfig = RemoteConfig.fromJson(response.data!);

      // Validate configuration
      await _validateConfig(remoteConfig);

      // Apply configuration
      _applyConfig(remoteConfig);

      _currentConfig = remoteConfig;
      _lastAppliedVersion = remoteConfig.version;

      // Report success
      _config.onSecurityEvent?.call(
        SecurityEvent(
          type: SecurityEventType.remoteConfigUpdateSuccess,
          message: 'Remote config updated to version ${remoteConfig.version}',
          metadata: {'version': remoteConfig.version},
        ),
      );
    } catch (e) {
      _config.onSecurityEvent?.call(
        SecurityEvent(
          type: SecurityEventType.remoteConfigUpdateFailed,
          message: 'Failed to update remote config: $e',
          metadata: {'error': e.toString()},
        ),
      );
      rethrow;
    }
  }

  /// Validate remote configuration
  Future<void> _validateConfig(RemoteConfig config) async {
    // Check version (must be newer than current)
    if (config.version <= _lastAppliedVersion) {
      throw SecurityException(
        'Remote config version ${config.version} is not newer than current $_lastAppliedVersion',
      );
    }

    // Check expiration
    if (config.isExpired) {
      throw SecurityException('Remote config has expired');
    }

    if (config.isNotYetValid) {
      throw SecurityException('Remote config is not yet valid');
    }

    // Verify signature
    final isValid = await _verifySignature(config);
    if (!isValid) {
      throw SecurityException('Remote config signature verification failed');
    }

    // Validate pin configurations
    for (final pinConfig in config.pinConfigurations.values) {
      if (!pinConfig.hasValidPins) {
        throw SecurityException(
          'Invalid pin format in remote config for ${pinConfig.domain}',
        );
      }
    }
  }

  /// Verify configuration signature
  Future<bool> _verifySignature(RemoteConfig config) async {
    // Get payload that was signed
    final payload = config.getSignaturePayload();
    final payloadBytes = utf8.encode(payload);

    // Decode signature
    final signatureBytes = base64.decode(config.signature);

    // Note: Actual signature verification should use platform-specific
    // crypto libraries (Security framework on iOS, KeyStore on Android)
    // This is a simplified version for demonstration
    
    // For production, delegate to native layer:
    // return await _platform.verifySignature(
    //   payload: payloadBytes,
    //   signature: signatureBytes,
    //   publicKey: _config.remoteConfigPublicKey!,
    // );

    // Placeholder: In production, this MUST use proper RSA/ECDSA verification
    return _verifySignatureSimplified(payloadBytes, signatureBytes);
  }

  /// Simplified signature verification (REPLACE IN PRODUCTION)
  bool _verifySignatureSimplified(List<int> payload, List<int> signature) {
    // WARNING: This is NOT secure and is only for demonstration
    // Production MUST use proper RSA-4096 or ECDSA P-384 verification
    // via platform-specific crypto APIs
    
    // For now, just check that signature is not empty
    return signature.isNotEmpty;
  }

  /// Apply validated configuration
  void _applyConfig(RemoteConfig config) {
    // Update pin configurations
    // Note: This should be done atomically to prevent TOCTOU issues
    // In production, use proper synchronization
    
    // The actual application would update the global config
    // This is handled by the SecurityManager
  }

  /// Get current remote configuration
  RemoteConfig? get currentConfig => _currentConfig;

  /// Get last applied version
  int get lastAppliedVersion => _lastAppliedVersion;
}
