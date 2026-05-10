// Copyright (c) 2026 Tomato Sentinel
// OWASP MASVS: MSTG-NETWORK-4
// SSL Public Key Pinning Service

import 'dart:convert';
import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import '../models/pin_configuration.dart';
import '../platform/method_channel_tomato_sentinel.dart';
import '../exceptions/security_exceptions.dart';

/// SSL Pinning Service
/// 
/// Implements SPKI (Subject Public Key Info) SHA-256 pinning.
/// Validates certificate chains against configured pins.
/// 
/// Threat Model:
/// - Compromised Certificate Authorities
/// - MITM with valid but unauthorized certificates
/// - Certificate substitution attacks
class SSLPinningService {
  final Map<String, PinConfiguration> _pinConfigurations;
  final MethodChannelTomatoSentinel _platform;

  SSLPinningService(this._pinConfigurations)
      : _platform = MethodChannelTomatoSentinel();

  /// Verify certificate chain against configured pins
  /// 
  /// Returns true if at least one pin matches.
  /// Throws [SSLPinningException] if no pins match and fail-closed is enabled.
  Future<bool> verifyPins({
    required String domain,
    required String certificateChain,
  }) async {
    final config = _getPinConfigForDomain(domain);
    
    if (config == null) {
      // No pinning configured for this domain
      return true;
    }

    // Check if configuration is expired
    if (config.isExpired) {
      throw SSLPinningException(
        'Pin configuration for $domain has expired',
        domain: domain,
      );
    }

    // Validate pins
    if (!config.hasValidPins) {
      throw SSLPinningException(
        'Invalid pin format for $domain',
        domain: domain,
      );
    }

    // Delegate to native layer for actual verification
    // Native layer extracts SPKI and computes SHA-256
    try {
      final isValid = await _platform.verifyPin(
        domain: domain,
        pins: config.pins,
        certificateChain: certificateChain,
      );

      if (!isValid) {
        throw SSLPinningException(
          'SSL pinning verification failed for $domain',
          domain: domain,
        );
      }

      return true;
    } catch (e) {
      throw SSLPinningException(
        'SSL pinning verification error: $e',
        domain: domain,
      );
    }
  }

  /// Get pin configuration for domain
  PinConfiguration? _getPinConfigForDomain(String domain) {
    // Exact match
    if (_pinConfigurations.containsKey(domain)) {
      return _pinConfigurations[domain];
    }

    // Check for subdomain matches
    for (final entry in _pinConfigurations.entries) {
      if (entry.value.includeSubdomains && _isSubdomain(domain, entry.key)) {
        return entry.value;
      }
    }

    return null;
  }

  /// Check if domain is a subdomain of parent
  bool _isSubdomain(String domain, String parent) {
    return domain.endsWith('.$parent');
  }

  /// Update pin configurations (from remote config)
  void updatePinConfigurations(Map<String, PinConfiguration> newConfigs) {
    _pinConfigurations.clear();
    _pinConfigurations.addAll(newConfigs);
  }

  /// Get current pin configurations
  Map<String, PinConfiguration> get pinConfigurations =>
      Map.unmodifiable(_pinConfigurations);

  /// Compute SPKI SHA-256 hash from certificate (for pin generation)
  /// This is a utility method for developers to generate pins
  static String computeSPKIHash(Uint8List certificateBytes) {
    // Note: Actual SPKI extraction should be done with proper ASN.1 parsing
    // This is a simplified version for demonstration
    final hash = sha256.convert(certificateBytes);
    return base64.encode(hash.bytes);
  }
}
