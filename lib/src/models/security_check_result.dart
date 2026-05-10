// Copyright (c) 2026 Tomato Sentinel

import 'package:meta/meta.dart';
import 'security_threat.dart';

/// Result of a security check operation
@immutable
class SecurityCheckResult {
  final bool isSecure;
  final List<SecurityThreat> threats;
  final DateTime checkedAt;
  final String checkType;

  const SecurityCheckResult({
    required this.isSecure,
    required this.threats,
    required this.checkedAt,
    required this.checkType,
  });

  factory SecurityCheckResult.secure(String checkType) {
    return SecurityCheckResult(
      isSecure: true,
      threats: const [],
      checkedAt: DateTime.now(),
      checkType: checkType,
    );
  }

  factory SecurityCheckResult.insecure({
    required String checkType,
    required List<SecurityThreat> threats,
  }) {
    return SecurityCheckResult(
      isSecure: false,
      threats: threats,
      checkedAt: DateTime.now(),
      checkType: checkType,
    );
  }

  bool get hasCriticalThreats {
    return threats.any((t) => t.severity == ThreatSeverity.critical);
  }

  bool get hasHighThreats {
    return threats.any((t) => t.severity.index >= ThreatSeverity.high.index);
  }

  ThreatSeverity get maxSeverity {
    if (threats.isEmpty) return ThreatSeverity.info;
    return threats.map((t) => t.severity).reduce(
          (a, b) => a.index > b.index ? a : b,
        );
  }

  @override
  String toString() {
    return 'SecurityCheckResult(isSecure: $isSecure, checkType: $checkType, threats: ${threats.length})';
  }
}

/// Aggregated security status
@immutable
class SecurityStatus {
  final bool isDeviceSecure;
  final Map<String, SecurityCheckResult> checkResults;
  final DateTime lastChecked;

  const SecurityStatus({
    required this.isDeviceSecure,
    required this.checkResults,
    required this.lastChecked,
  });

  factory SecurityStatus.initial() {
    return SecurityStatus(
      isDeviceSecure: true,
      checkResults: const {},
      lastChecked: DateTime.now(),
    );
  }

  List<SecurityThreat> get allThreats {
    return checkResults.values.expand((r) => r.threats).toList();
  }

  bool get hasCriticalThreats {
    return checkResults.values.any((r) => r.hasCriticalThreats);
  }

  SecurityStatus copyWith({
    bool? isDeviceSecure,
    Map<String, SecurityCheckResult>? checkResults,
    DateTime? lastChecked,
  }) {
    return SecurityStatus(
      isDeviceSecure: isDeviceSecure ?? this.isDeviceSecure,
      checkResults: checkResults ?? this.checkResults,
      lastChecked: lastChecked ?? this.lastChecked,
    );
  }
}
