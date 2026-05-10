// Copyright (c) 2026 Tomato Sentinel
// Unit tests: SSLPinningService

import 'dart:convert';
import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:tomato_sentinel/tomato_sentinel.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  const MethodChannel channel = MethodChannel('tomato_sentinel');

  const validPin1 = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';
  const validPin2 = 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=';

  setUp(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (MethodCall call) async {
      if (call.method == 'verifyPin') {
        final args = call.arguments as Map;
        final pins = args['pins'] as List;
        // Simulate: return true if first pin matches a known good pin
        return pins.contains(validPin1);
      }
      return null;
    });
  });

  tearDown(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, null);
  });

  group('SSLPinningService', () {
    test('verifyPins returns true when pin matches', () async {
      final service = SSLPinningService({
        'api.example.com': PinConfiguration(
          domain: 'api.example.com',
          pins: [validPin1, validPin2],
        ),
      });

      final result = await service.verifyPins(
        domain: 'api.example.com',
        certificateChain: 'dGVzdA==',
      );

      expect(result, isTrue);
    });

    test('verifyPins returns true when no pin config for domain', () async {
      final service = SSLPinningService({});

      final result = await service.verifyPins(
        domain: 'unpinned.example.com',
        certificateChain: 'dGVzdA==',
      );

      expect(result, isTrue);
    });

    test('verifyPins throws SSLPinningException when pin does not match', () async {
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (MethodCall call) async {
        if (call.method == 'verifyPin') return false;
        return null;
      });

      final service = SSLPinningService({
        'api.example.com': PinConfiguration(
          domain: 'api.example.com',
          pins: [validPin1, validPin2],
        ),
      });

      expect(
        () => service.verifyPins(
          domain: 'api.example.com',
          certificateChain: 'dGVzdA==',
        ),
        throwsA(isA<SSLPinningException>()),
      );
    });

    test('verifyPins throws SSLPinningException when config is expired', () async {
      final service = SSLPinningService({
        'api.example.com': PinConfiguration(
          domain: 'api.example.com',
          pins: [validPin1, validPin2],
          expiresAt: DateTime.now().subtract(const Duration(days: 1)),
        ),
      });

      expect(
        () => service.verifyPins(
          domain: 'api.example.com',
          certificateChain: 'dGVzdA==',
        ),
        throwsA(isA<SSLPinningException>()),
      );
    });

    test('verifyPins throws SSLPinningException when pins are invalid format', () async {
      final service = SSLPinningService({
        'api.example.com': PinConfiguration(
          domain: 'api.example.com',
          pins: ['invalid-pin-1', 'invalid-pin-2'],
        ),
      });

      expect(
        () => service.verifyPins(
          domain: 'api.example.com',
          certificateChain: 'dGVzdA==',
        ),
        throwsA(isA<SSLPinningException>()),
      );
    });

    test('verifyPins matches subdomain when includeSubdomains is true', () async {
      final service = SSLPinningService({
        'example.com': PinConfiguration(
          domain: 'example.com',
          pins: [validPin1, validPin2],
          includeSubdomains: true,
        ),
      });

      // Should use the parent domain's pin config for subdomain
      final result = await service.verifyPins(
        domain: 'api.example.com',
        certificateChain: 'dGVzdA==',
      );

      expect(result, isTrue);
    });

    test('verifyPins does not match subdomain when includeSubdomains is false', () async {
      final service = SSLPinningService({
        'example.com': PinConfiguration(
          domain: 'example.com',
          pins: [validPin1, validPin2],
          includeSubdomains: false,
        ),
      });

      // No config for subdomain, should return true (no pinning)
      final result = await service.verifyPins(
        domain: 'api.example.com',
        certificateChain: 'dGVzdA==',
      );

      expect(result, isTrue);
    });

    test('updatePinConfigurations replaces existing configs', () {
      final service = SSLPinningService({
        'old.example.com': PinConfiguration(
          domain: 'old.example.com',
          pins: [validPin1, validPin2],
        ),
      });

      service.updatePinConfigurations({
        'new.example.com': PinConfiguration(
          domain: 'new.example.com',
          pins: [validPin1, validPin2],
        ),
      });

      expect(service.pinConfigurations.containsKey('new.example.com'), isTrue);
      expect(service.pinConfigurations.containsKey('old.example.com'), isFalse);
    });

    test('pinConfigurations returns unmodifiable map', () {
      final service = SSLPinningService({});

      expect(
        () => service.pinConfigurations['test'] = PinConfiguration(
          domain: 'test',
          pins: [validPin1, validPin2],
        ),
        throwsUnsupportedError,
      );
    });
  });

  group('SSLPinningService.computeSPKIHash()', () {
    test('returns non-empty Base64 string', () {
      final bytes = Uint8List.fromList(List.generate(32, (i) => i));
      final hash = SSLPinningService.computeSPKIHash(bytes);

      expect(hash, isNotEmpty);
      // Should be valid Base64
      expect(() => base64.decode(hash), returnsNormally);
    });

    test('same input produces same hash', () {
      final bytes = Uint8List.fromList(List.generate(64, (i) => i % 256));
      final hash1 = SSLPinningService.computeSPKIHash(bytes);
      final hash2 = SSLPinningService.computeSPKIHash(bytes);

      expect(hash1, equals(hash2));
    });

    test('different inputs produce different hashes', () {
      final bytes1 = Uint8List.fromList(List.generate(32, (i) => i));
      final bytes2 = Uint8List.fromList(List.generate(32, (i) => 255 - i));

      final hash1 = SSLPinningService.computeSPKIHash(bytes1);
      final hash2 = SSLPinningService.computeSPKIHash(bytes2);

      expect(hash1, isNot(equals(hash2)));
    });
  });
}
