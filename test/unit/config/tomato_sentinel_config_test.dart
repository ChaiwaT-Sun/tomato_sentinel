// Copyright (c) 2026 Tomato Sentinel
// Unit tests: TomatoSentinelConfig

import 'package:flutter_test/flutter_test.dart';
import 'package:tomato_sentinel/tomato_sentinel.dart';

void main() {
  const validPin1 = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';
  const validPin2 = 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=';

  PinConfiguration makePinConfig(String domain) {
    return PinConfiguration(
      domain: domain,
      pins: [validPin1, validPin2],
    );
  }

  group('TomatoSentinelConfig.development()', () {
    test('disables all security checks', () {
      final config = TomatoSentinelConfig.development();

      expect(config.enableRootDetection, isFalse);
      expect(config.enableEmulatorDetection, isFalse);
      expect(config.enableHookDetection, isFalse);
      expect(config.enableTamperDetection, isFalse);
      expect(config.enableIntegrityCheck, isFalse);
    });

    test('sets failClosed to false', () {
      final config = TomatoSentinelConfig.development();
      expect(config.failClosed, isFalse);
    });

    test('sets enforceInDebugMode to false', () {
      final config = TomatoSentinelConfig.development();
      expect(config.enforceInDebugMode, isFalse);
    });

    test('accepts optional pin configurations', () {
      final config = TomatoSentinelConfig.development(
        pinConfigurations: {'api.example.com': makePinConfig('api.example.com')},
      );

      expect(config.pinConfigurations, isNotEmpty);
    });

    test('uses empty pin configurations by default', () {
      final config = TomatoSentinelConfig.development();
      expect(config.pinConfigurations, isEmpty);
    });
  });

  group('TomatoSentinelConfig.production()', () {
    test('enables all security checks', () {
      final config = TomatoSentinelConfig.production(
        pinConfigurations: {'api.example.com': makePinConfig('api.example.com')},
        remoteConfigUrl: 'https://example.com/config',
        remoteConfigPublicKey: 'test-key',
      );

      expect(config.enableRootDetection, isTrue);
      expect(config.enableEmulatorDetection, isTrue);
      expect(config.enableHookDetection, isTrue);
      expect(config.enableTamperDetection, isTrue);
      expect(config.enableIntegrityCheck, isTrue);
    });

    test('sets failClosed to true', () {
      final config = TomatoSentinelConfig.production(
        pinConfigurations: {'api.example.com': makePinConfig('api.example.com')},
        remoteConfigUrl: 'https://example.com/config',
        remoteConfigPublicKey: 'test-key',
      );

      expect(config.failClosed, isTrue);
    });

    test('sets enforceInDebugMode to true', () {
      final config = TomatoSentinelConfig.production(
        pinConfigurations: {'api.example.com': makePinConfig('api.example.com')},
        remoteConfigUrl: 'https://example.com/config',
        remoteConfigPublicKey: 'test-key',
      );

      expect(config.enforceInDebugMode, isTrue);
    });

    test('throws AssertionError when pinConfigurations is empty', () {
      expect(
        () => TomatoSentinelConfig.production(
          pinConfigurations: {},
          remoteConfigUrl: 'https://example.com/config',
          remoteConfigPublicKey: 'test-key',
        ),
        throwsA(isA<AssertionError>()),
      );
    });

    test('throws AssertionError when remoteConfigPublicKey is empty', () {
      expect(
        () => TomatoSentinelConfig.production(
          pinConfigurations: {'api.example.com': makePinConfig('api.example.com')},
          remoteConfigUrl: 'https://example.com/config',
          remoteConfigPublicKey: '',
        ),
        throwsA(isA<AssertionError>()),
      );
    });

    test('stores optional platform-specific fields', () {
      final config = TomatoSentinelConfig.production(
        pinConfigurations: {'api.example.com': makePinConfig('api.example.com')},
        remoteConfigUrl: 'https://example.com/config',
        remoteConfigPublicKey: 'test-key',
        playIntegrityCloudProjectNumber: '123456789',
        appAttestKeyId: 'com.example.app.attest',
      );

      expect(config.playIntegrityCloudProjectNumber, '123456789');
      expect(config.appAttestKeyId, 'com.example.app.attest');
    });

    test('stores security event callback', () {
      bool callbackCalled = false;
      final config = TomatoSentinelConfig.production(
        pinConfigurations: {'api.example.com': makePinConfig('api.example.com')},
        remoteConfigUrl: 'https://example.com/config',
        remoteConfigPublicKey: 'test-key',
        onSecurityEvent: (_) => callbackCalled = true,
      );

      config.onSecurityEvent?.call(
        SecurityEvent(
          type: SecurityEventType.rootDetected,
          message: 'test',
        ),
      );

      expect(callbackCalled, isTrue);
    });
  });

  group('TomatoSentinelConfig.copyWith()', () {
    test('creates modified copy preserving unchanged fields', () {
      final original = TomatoSentinelConfig.development();
      final copy = original.copyWith(
        enableRootDetection: true,
        failClosed: true,
      );

      expect(copy.enableRootDetection, isTrue);
      expect(copy.failClosed, isTrue);
      // Unchanged fields preserved
      expect(copy.enableEmulatorDetection, isFalse);
      expect(copy.enableHookDetection, isFalse);
    });

    test('copyWith with new pin configurations', () {
      final original = TomatoSentinelConfig.development();
      final newPins = {'api.example.com': makePinConfig('api.example.com')};
      final copy = original.copyWith(pinConfigurations: newPins);

      expect(copy.pinConfigurations, equals(newPins));
    });

    test('copyWith with new interval', () {
      final original = TomatoSentinelConfig.development();
      final copy = original.copyWith(
        integrityCheckInterval: const Duration(minutes: 10),
      );

      expect(copy.integrityCheckInterval, const Duration(minutes: 10));
    });
  });

  group('SecurityEvent', () {
    test('creates with required fields', () {
      final event = SecurityEvent(
        type: SecurityEventType.rootDetected,
        message: 'Root detected',
      );

      expect(event.type, SecurityEventType.rootDetected);
      expect(event.message, 'Root detected');
      expect(event.timestamp, isA<DateTime>());
      expect(event.metadata, isNull);
    });

    test('creates with metadata', () {
      final event = SecurityEvent(
        type: SecurityEventType.pinningViolation,
        message: 'Pin mismatch',
        metadata: {'domain': 'api.example.com'},
      );

      expect(event.metadata!['domain'], 'api.example.com');
    });

    test('all SecurityEventType values are defined', () {
      expect(SecurityEventType.values, contains(SecurityEventType.rootDetected));
      expect(SecurityEventType.values, contains(SecurityEventType.emulatorDetected));
      expect(SecurityEventType.values, contains(SecurityEventType.hookDetected));
      expect(SecurityEventType.values, contains(SecurityEventType.tamperDetected));
      expect(SecurityEventType.values, contains(SecurityEventType.pinningViolation));
      expect(SecurityEventType.values, contains(SecurityEventType.integrityCheckFailed));
    });
  });
}
