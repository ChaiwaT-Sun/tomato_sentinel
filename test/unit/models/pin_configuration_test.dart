// Copyright (c) 2026 Tomato Sentinel
// Unit tests: PinConfiguration model

import 'package:flutter_test/flutter_test.dart';
import 'package:tomato_sentinel/tomato_sentinel.dart';

void main() {
  // Valid SHA-256 SPKI pins (44 chars Base64)
  const validPin1 = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';
  const validPin2 = 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=';
  const validPin3 = 'YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2Fuihg=';

  group('PinConfiguration', () {
    test('creates with valid pins', () {
      final config = PinConfiguration(
        domain: 'api.example.com',
        pins: [validPin1, validPin2],
      );

      expect(config.domain, 'api.example.com');
      expect(config.pins.length, 2);
      expect(config.includeSubdomains, isFalse);
      expect(config.allowDebugBypass, isFalse);
    });

    test('throws AssertionError with fewer than 2 pins', () {
      expect(
        () => PinConfiguration(
          domain: 'api.example.com',
          pins: [validPin1],
        ),
        throwsA(isA<AssertionError>()),
      );
    });

    test('throws AssertionError with empty pins', () {
      expect(
        () => PinConfiguration(
          domain: 'api.example.com',
          pins: [],
        ),
        throwsA(isA<AssertionError>()),
      );
    });

    test('validatePinFormat accepts valid Base64 SHA-256', () {
      final config = PinConfiguration(
        domain: 'example.com',
        pins: [validPin1, validPin2],
      );

      expect(config.validatePinFormat(validPin1), isTrue);
      expect(config.validatePinFormat(validPin2), isTrue);
      expect(config.validatePinFormat(validPin3), isTrue);
    });

    test('validatePinFormat rejects invalid pins', () {
      final config = PinConfiguration(
        domain: 'example.com',
        pins: [validPin1, validPin2],
      );

      expect(config.validatePinFormat('invalid'), isFalse);
      expect(config.validatePinFormat(''), isFalse);
      expect(config.validatePinFormat('tooshort='), isFalse);
      // 43 chars without trailing = (wrong length)
      expect(config.validatePinFormat('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'), isFalse);
    });

    test('hasValidPins returns true when all pins are valid', () {
      final config = PinConfiguration(
        domain: 'example.com',
        pins: [validPin1, validPin2],
      );

      expect(config.hasValidPins, isTrue);
    });

    test('hasValidPins returns false when any pin is invalid', () {
      final config = PinConfiguration(
        domain: 'example.com',
        pins: [validPin1, 'invalid-pin'],
      );

      expect(config.hasValidPins, isFalse);
    });

    test('isExpired returns false when no expiry set', () {
      final config = PinConfiguration(
        domain: 'example.com',
        pins: [validPin1, validPin2],
      );

      expect(config.isExpired, isFalse);
    });

    test('isExpired returns true when past expiry', () {
      final config = PinConfiguration(
        domain: 'example.com',
        pins: [validPin1, validPin2],
        expiresAt: DateTime.now().subtract(const Duration(days: 1)),
      );

      expect(config.isExpired, isTrue);
    });

    test('isExpired returns false when future expiry', () {
      final config = PinConfiguration(
        domain: 'example.com',
        pins: [validPin1, validPin2],
        expiresAt: DateTime.now().add(const Duration(days: 90)),
      );

      expect(config.isExpired, isFalse);
    });

    test('toJson and fromJson round-trip', () {
      final original = PinConfiguration(
        domain: 'api.example.com',
        pins: [validPin1, validPin2],
        includeSubdomains: true,
        expiresAt: DateTime(2027, 1, 1),
        allowDebugBypass: false,
      );

      final json = original.toJson();
      final restored = PinConfiguration.fromJson(json);

      expect(restored.domain, original.domain);
      expect(restored.pins, original.pins);
      expect(restored.includeSubdomains, original.includeSubdomains);
      expect(restored.allowDebugBypass, original.allowDebugBypass);
    });

    test('copyWith creates modified copy', () {
      final original = PinConfiguration(
        domain: 'example.com',
        pins: [validPin1, validPin2],
      );

      final copy = original.copyWith(
        domain: 'new.example.com',
        includeSubdomains: true,
      );

      expect(copy.domain, 'new.example.com');
      expect(copy.includeSubdomains, isTrue);
      expect(copy.pins, original.pins);
    });

    test('equality works correctly', () {
      final a = PinConfiguration(
        domain: 'example.com',
        pins: [validPin1, validPin2],
      );
      final b = PinConfiguration(
        domain: 'example.com',
        pins: [validPin1, validPin2],
      );
      final c = PinConfiguration(
        domain: 'other.com',
        pins: [validPin1, validPin2],
      );

      expect(a, equals(b));
      expect(a, isNot(equals(c)));
    });
  });

  group('PinConfigurationBuilder', () {
    test('builds valid configuration', () {
      final config = PinConfigurationBuilder()
          .domain('api.example.com')
          .addPin(validPin1)
          .addPin(validPin2)
          .includeSubdomains(true)
          .expiresAt(DateTime(2027, 12, 31))
          .build();

      expect(config.domain, 'api.example.com');
      expect(config.pins.length, 2);
      expect(config.includeSubdomains, isTrue);
    });

    test('addPins adds multiple pins at once', () {
      final config = PinConfigurationBuilder()
          .domain('example.com')
          .addPins([validPin1, validPin2, validPin3])
          .build();

      expect(config.pins.length, 3);
    });

    test('throws when domain not set', () {
      expect(
        () => PinConfigurationBuilder()
            .addPin(validPin1)
            .addPin(validPin2)
            .build(),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('throws when fewer than 2 pins', () {
      expect(
        () => PinConfigurationBuilder()
            .domain('example.com')
            .addPin(validPin1)
            .build(),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('pins list is unmodifiable after build', () {
      final config = PinConfigurationBuilder()
          .domain('example.com')
          .addPin(validPin1)
          .addPin(validPin2)
          .build();

      expect(() => (config.pins as List).add(validPin3), throwsUnsupportedError);
    });
  });
}
