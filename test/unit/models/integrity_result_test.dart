// Copyright (c) 2026 Tomato Sentinel
// Unit tests: IntegrityResult models

import 'package:flutter_test/flutter_test.dart';
import 'package:tomato_sentinel/tomato_sentinel.dart';

void main() {
  group('IntegrityResult', () {
    test('valid() factory creates valid result', () {
      final result = IntegrityResult.valid(
        verdict: IntegrityVerdict.genuine,
        token: 'test-token',
        details: {'source': 'play_integrity'},
      );

      expect(result.isValid, isTrue);
      expect(result.verdict, IntegrityVerdict.genuine);
      expect(result.token, 'test-token');
      expect(result.details['source'], 'play_integrity');
      expect(result.checkedAt, isA<DateTime>());
    });

    test('invalid() factory creates invalid result', () {
      final result = IntegrityResult.invalid(
        verdict: IntegrityVerdict.compromised,
        details: {'reason': 'rooted'},
      );

      expect(result.isValid, isFalse);
      expect(result.verdict, IntegrityVerdict.compromised);
      expect(result.details['reason'], 'rooted');
    });

    test('toString contains isValid and verdict', () {
      final result = IntegrityResult.valid(verdict: IntegrityVerdict.strong);
      expect(result.toString(), contains('isValid: true'));
      expect(result.toString(), contains('strong'));
    });
  });

  group('PlayIntegrityResult', () {
    test('fromNative maps strong integrity correctly', () {
      final data = {
        'meetsDeviceIntegrity': true,
        'meetsBasicIntegrity': true,
        'meetsStrongIntegrity': true,
        'appRecognitionVerdict': 'PLAY_RECOGNIZED',
        'token': 'play-token',
      };

      final result = PlayIntegrityResult.fromNative(data);

      expect(result.isValid, isTrue);
      expect(result.verdict, IntegrityVerdict.strong);
      expect(result.meetsStrongIntegrity, isTrue);
      expect(result.meetsDeviceIntegrity, isTrue);
      expect(result.meetsBasicIntegrity, isTrue);
      expect(result.appRecognitionVerdict, 'PLAY_RECOGNIZED');
    });

    test('fromNative maps device integrity (not strong)', () {
      final data = {
        'meetsDeviceIntegrity': true,
        'meetsBasicIntegrity': true,
        'meetsStrongIntegrity': false,
      };

      final result = PlayIntegrityResult.fromNative(data);

      expect(result.isValid, isTrue);
      expect(result.verdict, IntegrityVerdict.genuine);
    });

    test('fromNative maps basic integrity only', () {
      final data = {
        'meetsDeviceIntegrity': false,
        'meetsBasicIntegrity': true,
        'meetsStrongIntegrity': false,
      };

      final result = PlayIntegrityResult.fromNative(data);

      expect(result.isValid, isTrue);
      expect(result.verdict, IntegrityVerdict.basic);
    });

    test('fromNative maps failed integrity', () {
      final data = {
        'meetsDeviceIntegrity': false,
        'meetsBasicIntegrity': false,
        'meetsStrongIntegrity': false,
      };

      final result = PlayIntegrityResult.fromNative(data);

      expect(result.isValid, isFalse);
      expect(result.verdict, IntegrityVerdict.failed);
    });

    test('fromNative handles missing fields gracefully', () {
      final result = PlayIntegrityResult.fromNative({});

      expect(result.isValid, isFalse);
      expect(result.meetsDeviceIntegrity, isFalse);
      expect(result.meetsBasicIntegrity, isFalse);
      expect(result.meetsStrongIntegrity, isFalse);
    });
  });

  group('AppAttestResult', () {
    test('fromNative maps valid attestation', () {
      final data = {
        'isValid': true,
        'isKeyValid': true,
        'keyId': 'key-123',
        'attestation': 'base64attestation',
        'token': 'attest-token',
      };

      final result = AppAttestResult.fromNative(data);

      expect(result.isValid, isTrue);
      expect(result.verdict, IntegrityVerdict.genuine);
      expect(result.keyId, 'key-123');
      expect(result.isKeyValid, isTrue);
    });

    test('fromNative maps jailbroken device', () {
      final data = {
        'isValid': false,
        'isKeyValid': false,
        'isJailbroken': true,
      };

      final result = AppAttestResult.fromNative(data);

      expect(result.isValid, isFalse);
      expect(result.verdict, IntegrityVerdict.compromised);
    });

    test('fromNative maps failed attestation', () {
      final data = {
        'isValid': false,
        'isKeyValid': false,
        'isJailbroken': false,
      };

      final result = AppAttestResult.fromNative(data);

      expect(result.isValid, isFalse);
      expect(result.verdict, IntegrityVerdict.failed);
    });

    test('fromNative handles missing fields gracefully', () {
      final result = AppAttestResult.fromNative({});

      expect(result.isValid, isFalse);
      expect(result.isKeyValid, isFalse);
    });
  });

  group('IntegrityVerdict', () {
    test('all verdict values are defined', () {
      expect(IntegrityVerdict.values, contains(IntegrityVerdict.genuine));
      expect(IntegrityVerdict.values, contains(IntegrityVerdict.basic));
      expect(IntegrityVerdict.values, contains(IntegrityVerdict.strong));
      expect(IntegrityVerdict.values, contains(IntegrityVerdict.compromised));
      expect(IntegrityVerdict.values, contains(IntegrityVerdict.emulator));
      expect(IntegrityVerdict.values, contains(IntegrityVerdict.tampered));
      expect(IntegrityVerdict.values, contains(IntegrityVerdict.failed));
      expect(IntegrityVerdict.values, contains(IntegrityVerdict.unavailable));
    });
  });
}
