// Copyright (c) 2026 Tomato Sentinel
// Platform channel implementation

import 'package:flutter/services.dart';

/// Method channel implementation for native platform communication
class MethodChannelTomatoSentinel {
  static const MethodChannel _channel = MethodChannel('tomato_sentinel');
  static const EventChannel _eventChannel = EventChannel('tomato_sentinel/events');

  /// Check if device is rooted/jailbroken
  Future<bool> isDeviceRooted() async {
    try {
      final result = await _channel.invokeMethod<bool>('isDeviceRooted');
      return result ?? false;
    } on PlatformException catch (e) {
      throw _handlePlatformException(e);
    }
  }

  /// Check if running in emulator
  Future<bool> isEmulator() async {
    try {
      final result = await _channel.invokeMethod<bool>('isEmulator');
      return result ?? false;
    } on PlatformException catch (e) {
      throw _handlePlatformException(e);
    }
  }

  /// Check if hooking frameworks are present
  Future<bool> isHooked() async {
    try {
      final result = await _channel.invokeMethod<bool>('isHooked');
      return result ?? false;
    } on PlatformException catch (e) {
      throw _handlePlatformException(e);
    }
  }

  /// Check if app has been tampered with
  Future<bool> isTampered() async {
    try {
      final result = await _channel.invokeMethod<bool>('isTampered');
      return result ?? false;
    } on PlatformException catch (e) {
      throw _handlePlatformException(e);
    }
  }

  /// Verify SSL certificate pins
  Future<bool> verifyPin({
    required String domain,
    required List<String> pins,
    required String certificateChain,
  }) async {
    try {
      final result = await _channel.invokeMethod<bool>('verifyPin', {
        'domain': domain,
        'pins': pins,
        'certificateChain': certificateChain,
      });
      return result ?? false;
    } on PlatformException catch (e) {
      throw _handlePlatformException(e);
    }
  }

  /// Check device integrity (Play Integrity / App Attest)
  Future<Map<String, dynamic>> checkIntegrity() async {
    try {
      final result = await _channel.invokeMethod<Map>('checkIntegrity');
      return Map<String, dynamic>.from(result ?? {});
    } on PlatformException catch (e) {
      throw _handlePlatformException(e);
    }
  }

  /// Initialize Play Integrity API (Android only)
  Future<void> initializePlayIntegrity(String cloudProjectNumber) async {
    try {
      await _channel.invokeMethod('initializePlayIntegrity', {
        'cloudProjectNumber': cloudProjectNumber,
      });
    } on PlatformException catch (e) {
      throw _handlePlatformException(e);
    }
  }

  /// Initialize App Attest (iOS only)
  Future<void> initializeAppAttest(String keyId) async {
    try {
      await _channel.invokeMethod('initializeAppAttest', {
        'keyId': keyId,
      });
    } on PlatformException catch (e) {
      throw _handlePlatformException(e);
    }
  }

  /// Get platform version
  Future<String?> getPlatformVersion() async {
    try {
      return await _channel.invokeMethod<String>('getPlatformVersion');
    } on PlatformException catch (e) {
      throw _handlePlatformException(e);
    }
  }

  /// Stream of security events from native layer
  Stream<Map<String, dynamic>> get securityEventStream {
    return _eventChannel.receiveBroadcastStream().map((event) {
      return Map<String, dynamic>.from(event as Map);
    });
  }

  /// Handle platform exceptions
  Exception _handlePlatformException(PlatformException e) {
    return Exception('Platform error: ${e.code} - ${e.message}');
  }
}
