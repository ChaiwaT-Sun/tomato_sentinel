// Copyright (c) 2026 Tomato Sentinel
// Security threat model definitions

import 'package:meta/meta.dart';

/// Represents a detected security threat
@immutable
class SecurityThreat {
  final ThreatType type;
  final ThreatSeverity severity;
  final String description;
  final Map<String, dynamic> details;
  final DateTime detectedAt;

  const SecurityThreat._({
    required this.type,
    required this.severity,
    required this.description,
    required this.details,
    required this.detectedAt,
  });

  factory SecurityThreat.create({
    required ThreatType type,
    required ThreatSeverity severity,
    required String description,
    Map<String, dynamic>? details,
  }) {
    return SecurityThreat._(
      type: type,
      severity: severity,
      description: description,
      details: details ?? {},
      detectedAt: DateTime.now(),
    );
  }

  @override
  String toString() {
    return 'SecurityThreat(type: $type, severity: $severity, description: $description)';
  }

  @override
  bool operator ==(Object other) {
    if (identical(this, other)) return true;
    return other is SecurityThreat &&
        other.type == type &&
        other.severity == severity &&
        other.description == description;
  }

  @override
  int get hashCode => Object.hash(type, severity, description);
}

/// Types of security threats
/// Aligned with OWASP MASVS categories
enum ThreatType {
  /// Device is rooted (Android) or jailbroken (iOS)
  /// MASVS: MSTG-RESILIENCE-1
  rootedDevice,

  /// Running in emulator/simulator
  /// MASVS: MSTG-RESILIENCE-5
  emulatorDetected,

  /// Frida, Xposed, Cydia Substrate detected
  /// MASVS: MSTG-RESILIENCE-4
  hookingFrameworkDetected,

  /// Binary has been tampered with
  /// MASVS: MSTG-RESILIENCE-3
  tamperingDetected,

  /// SSL pinning violation
  /// MASVS: MSTG-NETWORK-4
  sslPinningViolation,

  /// Debugger attached
  /// MASVS: MSTG-RESILIENCE-2
  debuggerDetected,

  /// Play Integrity / App Attest failed
  /// MASVS: MSTG-RESILIENCE-1
  integrityCheckFailed,

  /// Unknown or generic threat
  unknown,
}

/// Severity levels for threats
enum ThreatSeverity {
  /// Informational - log only
  info,

  /// Low severity - monitor
  low,

  /// Medium severity - warn user
  medium,

  /// High severity - restrict functionality
  high,

  /// Critical - terminate application
  critical,
}

extension ThreatSeverityExtension on ThreatSeverity {
  bool get shouldTerminate => this == ThreatSeverity.critical;
  bool get shouldRestrict => index >= ThreatSeverity.high.index;
  bool get shouldWarn => index >= ThreatSeverity.medium.index;
}
