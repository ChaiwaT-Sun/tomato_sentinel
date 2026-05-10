// Copyright (c) 2026 Tomato Sentinel
// Security-related exceptions

/// Base security exception.
class SecurityException implements Exception {
  final String message;
  final dynamic cause;

  SecurityException(this.message, [this.cause]);

  @override
  String toString() {
    if (cause != null) {
      return 'SecurityException: $message\nCaused by: $cause';
    }
    return 'SecurityException: $message';
  }
}

/// Thrown when an SSL certificate does not match any configured pin.
class SSLPinningException extends SecurityException {
  final String domain;

  SSLPinningException(String message, {required this.domain, dynamic cause})
      : super(message, cause);

  @override
  String toString() {
    return 'SSLPinningException [$domain]: $message';
  }
}

/// Thrown when a rooted or jailbroken device is detected.
class RootDetectionException extends SecurityException {
  RootDetectionException(super.message, [super.cause]);
}

/// Thrown when an emulator or simulator is detected.
class EmulatorDetectionException extends SecurityException {
  EmulatorDetectionException(super.message, [super.cause]);
}

/// Thrown when a hooking framework (Frida, Xposed, etc.) is detected.
class HookDetectionException extends SecurityException {
  HookDetectionException(super.message, [super.cause]);
}

/// Thrown when binary tampering is detected.
class TamperDetectionException extends SecurityException {
  TamperDetectionException(super.message, [super.cause]);
}

/// Thrown when a Play Integrity or App Attest check fails.
class IntegrityCheckException extends SecurityException {
  IntegrityCheckException(super.message, [super.cause]);
}

/// Thrown when fetching or validating the remote configuration fails.
class RemoteConfigException extends SecurityException {
  RemoteConfigException(super.message, [super.cause]);
}
