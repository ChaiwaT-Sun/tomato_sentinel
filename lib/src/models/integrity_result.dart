// Copyright (c) 2026 Tomato Sentinel
// Play Integrity API / App Attest result models

import 'package:meta/meta.dart';

/// Result from Play Integrity API (Android) or App Attest (iOS)
@immutable
class IntegrityResult {
  final bool isValid;
  final IntegrityVerdict verdict;
  final String? token;
  final DateTime checkedAt;
  final Map<String, dynamic> details;

  const IntegrityResult({
    required this.isValid,
    required this.verdict,
    this.token,
    required this.checkedAt,
    this.details = const {},
  });

  factory IntegrityResult.valid({
    required IntegrityVerdict verdict,
    String? token,
    Map<String, dynamic>? details,
  }) {
    return IntegrityResult(
      isValid: true,
      verdict: verdict,
      token: token,
      checkedAt: DateTime.now(),
      details: details ?? {},
    );
  }

  factory IntegrityResult.invalid({
    required IntegrityVerdict verdict,
    Map<String, dynamic>? details,
  }) {
    return IntegrityResult(
      isValid: false,
      verdict: verdict,
      checkedAt: DateTime.now(),
      details: details ?? {},
    );
  }

  @override
  String toString() {
    return 'IntegrityResult(isValid: $isValid, verdict: $verdict)';
  }
}

/// Integrity verdict types
enum IntegrityVerdict {
  /// Device and app integrity verified (Play Integrity: MEETS_DEVICE_INTEGRITY)
  genuine,

  /// Basic integrity met but not strong (Play Integrity: MEETS_BASIC_INTEGRITY)
  basic,

  /// Strong integrity met (Play Integrity: MEETS_STRONG_INTEGRITY)
  strong,

  /// Device is rooted/jailbroken
  compromised,

  /// Running in emulator
  emulator,

  /// App has been tampered with
  tampered,

  /// Integrity check failed
  failed,

  /// Integrity check not available
  unavailable,
}

/// Play Integrity API specific result (Android)
@immutable
class PlayIntegrityResult extends IntegrityResult {
  final bool meetsDeviceIntegrity;
  final bool meetsBasicIntegrity;
  final bool meetsStrongIntegrity;
  final String? appRecognitionVerdict;

  const PlayIntegrityResult({
    required super.isValid,
    required super.verdict,
    super.token,
    required super.checkedAt,
    super.details,
    required this.meetsDeviceIntegrity,
    required this.meetsBasicIntegrity,
    required this.meetsStrongIntegrity,
    this.appRecognitionVerdict,
  });

  factory PlayIntegrityResult.fromNative(Map<String, dynamic> data) {
    final meetsDevice = data['meetsDeviceIntegrity'] as bool? ?? false;
    final meetsBasic = data['meetsBasicIntegrity'] as bool? ?? false;
    final meetsStrong = data['meetsStrongIntegrity'] as bool? ?? false;

    IntegrityVerdict verdict;
    if (meetsStrong) {
      verdict = IntegrityVerdict.strong;
    } else if (meetsDevice) {
      verdict = IntegrityVerdict.genuine;
    } else if (meetsBasic) {
      verdict = IntegrityVerdict.basic;
    } else {
      verdict = IntegrityVerdict.failed;
    }

    return PlayIntegrityResult(
      isValid: meetsDevice || meetsBasic,
      verdict: verdict,
      token: data['token'] as String?,
      checkedAt: DateTime.now(),
      details: data,
      meetsDeviceIntegrity: meetsDevice,
      meetsBasicIntegrity: meetsBasic,
      meetsStrongIntegrity: meetsStrong,
      appRecognitionVerdict: data['appRecognitionVerdict'] as String?,
    );
  }
}

/// App Attest specific result (iOS)
@immutable
class AppAttestResult extends IntegrityResult {
  final String? keyId;
  final String? attestation;
  final bool isKeyValid;

  const AppAttestResult({
    required super.isValid,
    required super.verdict,
    super.token,
    required super.checkedAt,
    super.details,
    this.keyId,
    this.attestation,
    required this.isKeyValid,
  });

  factory AppAttestResult.fromNative(Map<String, dynamic> data) {
    final isValid = data['isValid'] as bool? ?? false;
    final isKeyValid = data['isKeyValid'] as bool? ?? false;

    IntegrityVerdict verdict;
    if (isValid && isKeyValid) {
      verdict = IntegrityVerdict.genuine;
    } else if (data['isJailbroken'] as bool? ?? false) {
      verdict = IntegrityVerdict.compromised;
    } else {
      verdict = IntegrityVerdict.failed;
    }

    return AppAttestResult(
      isValid: isValid,
      verdict: verdict,
      token: data['token'] as String?,
      checkedAt: DateTime.now(),
      details: data,
      keyId: data['keyId'] as String?,
      attestation: data['attestation'] as String?,
      isKeyValid: isKeyValid,
    );
  }
}
