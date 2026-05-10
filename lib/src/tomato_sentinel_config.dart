// Copyright (c) 2026 Tomato Sentinel
// OWASP MASVS: MSTG-NETWORK-4, MSTG-RESILIENCE-1

import 'package:meta/meta.dart';
import 'models/pin_configuration.dart';

/// Production-grade security configuration
/// 
/// Threat Model:
/// - MITM attacks via compromised CA certificates
/// - Runtime manipulation (Frida, Xposed, Cydia Substrate)
/// - Rooted/Jailbroken device exploitation
/// - Emulator-based automated attacks
/// - Binary tampering and repackaging
/// - Debug/development build exploitation
@immutable
class TomatoSentinelConfig {
  /// SSL pinning configurations per domain
  final Map<String, PinConfiguration> pinConfigurations;

  /// Enable root/jailbreak detection
  final bool enableRootDetection;

  /// Enable emulator detection
  final bool enableEmulatorDetection;

  /// Enable Frida/hooking framework detection
  final bool enableHookDetection;

  /// Enable binary tamper detection
  final bool enableTamperDetection;

  /// Enable Play Integrity API (Android) / App Attest (iOS)
  final bool enableIntegrityCheck;

  /// Fail closed on security violations (recommended for production)
  final bool failClosed;

  /// Remote config URL for dynamic pin updates
  final String? remoteConfigUrl;

  /// Public key for verifying signed remote config (PEM format)
  /// MUST be RSA 4096-bit or ECDSA P-384 minimum
  final String? remoteConfigPublicKey;

  /// Security event reporting callback
  final SecurityEventCallback? onSecurityEvent;

  /// Allow security checks in debug mode (disable for development)
  final bool enforceInDebugMode;

  /// Minimum time between integrity checks (prevents DOS)
  final Duration integrityCheckInterval;

  /// Play Integrity API cloud project number (Android only)
  final String? playIntegrityCloudProjectNumber;

  /// App Attest key ID (iOS only)
  final String? appAttestKeyId;

  const TomatoSentinelConfig({
    required this.pinConfigurations,
    this.enableRootDetection = true,
    this.enableEmulatorDetection = true,
    this.enableHookDetection = true,
    this.enableTamperDetection = true,
    this.enableIntegrityCheck = true,
    this.failClosed = true,
    this.remoteConfigUrl,
    this.remoteConfigPublicKey,
    this.onSecurityEvent,
    this.enforceInDebugMode = false,
    this.integrityCheckInterval = const Duration(minutes: 5),
    this.playIntegrityCloudProjectNumber,
    this.appAttestKeyId,
  });

  /// Create a development-friendly configuration
  /// WARNING: Never use in production builds
  factory TomatoSentinelConfig.development({
    Map<String, PinConfiguration>? pinConfigurations,
  }) {
    return TomatoSentinelConfig(
      pinConfigurations: pinConfigurations ?? {},
      enableRootDetection: false,
      enableEmulatorDetection: false,
      enableHookDetection: false,
      enableTamperDetection: false,
      enableIntegrityCheck: false,
      failClosed: false,
      enforceInDebugMode: false,
    );
  }

  /// Create a production configuration with strict security
  factory TomatoSentinelConfig.production({
    required Map<String, PinConfiguration> pinConfigurations,
    required String remoteConfigUrl,
    required String remoteConfigPublicKey,
    String? playIntegrityCloudProjectNumber,
    String? appAttestKeyId,
    SecurityEventCallback? onSecurityEvent,
  }) {
    assert(pinConfigurations.isNotEmpty, 'Production must have pin configurations');
    assert(remoteConfigPublicKey.isNotEmpty, 'Production must have remote config public key');
    
    return TomatoSentinelConfig(
      pinConfigurations: pinConfigurations,
      enableRootDetection: true,
      enableEmulatorDetection: true,
      enableHookDetection: true,
      enableTamperDetection: true,
      enableIntegrityCheck: true,
      failClosed: true,
      remoteConfigUrl: remoteConfigUrl,
      remoteConfigPublicKey: remoteConfigPublicKey,
      onSecurityEvent: onSecurityEvent,
      enforceInDebugMode: true,
      playIntegrityCloudProjectNumber: playIntegrityCloudProjectNumber,
      appAttestKeyId: appAttestKeyId,
    );
  }

  TomatoSentinelConfig copyWith({
    Map<String, PinConfiguration>? pinConfigurations,
    bool? enableRootDetection,
    bool? enableEmulatorDetection,
    bool? enableHookDetection,
    bool? enableTamperDetection,
    bool? enableIntegrityCheck,
    bool? failClosed,
    String? remoteConfigUrl,
    String? remoteConfigPublicKey,
    SecurityEventCallback? onSecurityEvent,
    bool? enforceInDebugMode,
    Duration? integrityCheckInterval,
    String? playIntegrityCloudProjectNumber,
    String? appAttestKeyId,
  }) {
    return TomatoSentinelConfig(
      pinConfigurations: pinConfigurations ?? this.pinConfigurations,
      enableRootDetection: enableRootDetection ?? this.enableRootDetection,
      enableEmulatorDetection: enableEmulatorDetection ?? this.enableEmulatorDetection,
      enableHookDetection: enableHookDetection ?? this.enableHookDetection,
      enableTamperDetection: enableTamperDetection ?? this.enableTamperDetection,
      enableIntegrityCheck: enableIntegrityCheck ?? this.enableIntegrityCheck,
      failClosed: failClosed ?? this.failClosed,
      remoteConfigUrl: remoteConfigUrl ?? this.remoteConfigUrl,
      remoteConfigPublicKey: remoteConfigPublicKey ?? this.remoteConfigPublicKey,
      onSecurityEvent: onSecurityEvent ?? this.onSecurityEvent,
      enforceInDebugMode: enforceInDebugMode ?? this.enforceInDebugMode,
      integrityCheckInterval: integrityCheckInterval ?? this.integrityCheckInterval,
      playIntegrityCloudProjectNumber: playIntegrityCloudProjectNumber ?? this.playIntegrityCloudProjectNumber,
      appAttestKeyId: appAttestKeyId ?? this.appAttestKeyId,
    );
  }
}

/// Callback for security events
typedef SecurityEventCallback = void Function(SecurityEvent event);

// Internal mutable callback holder — allows re-wiring after initialize()
SecurityEventCallback? _globalSecurityEventCallback;

/// Read the currently registered global security event callback.
/// Used by SecurityManager to forward events to the UI layer.
SecurityEventCallback? get globalSecurityEventCallback =>
    _globalSecurityEventCallback;

extension TomatoSentinelConfigCallback on TomatoSentinelConfig {
  /// Override the security event callback after SDK initialization.
  ///
  /// Use this when the callback needs access to UI context (e.g. Riverpod
  /// providers) that is not available at the time [TomatoSentinel.initialize]
  /// is called.
  static void overrideSecurityEventCallback(SecurityEventCallback callback) {
    _globalSecurityEventCallback = callback;
  }
}

/// Security event types
class SecurityEvent {
  final SecurityEventType type;
  final String message;
  final DateTime timestamp;
  final Map<String, dynamic>? metadata;

  SecurityEvent({
    required this.type,
    required this.message,
    DateTime? timestamp,
    this.metadata,
  }) : timestamp = timestamp ?? DateTime.now();
}

enum SecurityEventType {
  rootDetected,
  jailbreakDetected,
  emulatorDetected,
  hookDetected,
  tamperDetected,
  pinningViolation,
  integrityCheckFailed,
  remoteConfigUpdateFailed,
  remoteConfigUpdateSuccess,
  securityCheckPassed,
}
