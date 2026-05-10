// Copyright (c) 2026 Tomato Sentinel
// Signed remote configuration for dynamic security updates

import 'package:meta/meta.dart';
import 'pin_configuration.dart';

/// Signed remote configuration
/// Uses RSA-4096 or ECDSA P-384 signature verification
/// 
/// Threat Model:
/// - Configuration tampering by MITM
/// - Unauthorized configuration updates
/// - Replay attacks with old configurations
@immutable
class RemoteConfig {
  /// Configuration version (monotonically increasing)
  final int version;

  /// Timestamp when config was created
  final DateTime createdAt;

  /// Expiration timestamp
  final DateTime expiresAt;

  /// Updated pin configurations
  final Map<String, PinConfiguration> pinConfigurations;

  /// Security policy updates
  final SecurityPolicy? securityPolicy;

  /// Digital signature (Base64 encoded)
  final String signature;

  /// Nonce to prevent replay attacks
  final String nonce;

  const RemoteConfig({
    required this.version,
    required this.createdAt,
    required this.expiresAt,
    required this.pinConfigurations,
    this.securityPolicy,
    required this.signature,
    required this.nonce,
  });

  /// Check if configuration is expired
  bool get isExpired => DateTime.now().isAfter(expiresAt);

  /// Check if configuration is not yet valid
  bool get isNotYetValid => DateTime.now().isBefore(createdAt);

  /// Check if configuration is currently valid
  bool get isValid => !isExpired && !isNotYetValid;

  /// Get payload for signature verification
  String getSignaturePayload() {
    return '$version|${createdAt.toIso8601String()}|${expiresAt.toIso8601String()}|$nonce';
  }

  Map<String, dynamic> toJson() {
    return {
      'version': version,
      'createdAt': createdAt.toIso8601String(),
      'expiresAt': expiresAt.toIso8601String(),
      'pinConfigurations': pinConfigurations.map(
        (key, value) => MapEntry(key, value.toJson()),
      ),
      'securityPolicy': securityPolicy?.toJson(),
      'signature': signature,
      'nonce': nonce,
    };
  }

  factory RemoteConfig.fromJson(Map<String, dynamic> json) {
    return RemoteConfig(
      version: json['version'] as int,
      createdAt: DateTime.parse(json['createdAt'] as String),
      expiresAt: DateTime.parse(json['expiresAt'] as String),
      pinConfigurations: (json['pinConfigurations'] as Map<String, dynamic>).map(
        (key, value) => MapEntry(
          key,
          PinConfiguration.fromJson(value as Map<String, dynamic>),
        ),
      ),
      securityPolicy: json['securityPolicy'] != null
          ? SecurityPolicy.fromJson(json['securityPolicy'] as Map<String, dynamic>)
          : null,
      signature: json['signature'] as String,
      nonce: json['nonce'] as String,
    );
  }
}

/// Security policy configuration
@immutable
class SecurityPolicy {
  final bool enforceRootDetection;
  final bool enforceEmulatorDetection;
  final bool enforceHookDetection;
  final bool enforceTamperDetection;
  final int minimumAppVersion;
  final List<String> blockedVersions;

  const SecurityPolicy({
    required this.enforceRootDetection,
    required this.enforceEmulatorDetection,
    required this.enforceHookDetection,
    required this.enforceTamperDetection,
    required this.minimumAppVersion,
    this.blockedVersions = const [],
  });

  Map<String, dynamic> toJson() {
    return {
      'enforceRootDetection': enforceRootDetection,
      'enforceEmulatorDetection': enforceEmulatorDetection,
      'enforceHookDetection': enforceHookDetection,
      'enforceTamperDetection': enforceTamperDetection,
      'minimumAppVersion': minimumAppVersion,
      'blockedVersions': blockedVersions,
    };
  }

  factory SecurityPolicy.fromJson(Map<String, dynamic> json) {
    return SecurityPolicy(
      enforceRootDetection: json['enforceRootDetection'] as bool,
      enforceEmulatorDetection: json['enforceEmulatorDetection'] as bool,
      enforceHookDetection: json['enforceHookDetection'] as bool,
      enforceTamperDetection: json['enforceTamperDetection'] as bool,
      minimumAppVersion: json['minimumAppVersion'] as int,
      blockedVersions: (json['blockedVersions'] as List?)?.cast<String>() ?? [],
    );
  }
}
