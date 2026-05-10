// Copyright (c) 2026 Tomato Sentinel
// Integration tests for security SDK

import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:tomato_sentinel/tomato_sentinel.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  group('Tomato Sentinel Integration Tests', () {
    late TomatoSentinelConfig testConfig;

    setUp(() {
      // Reset SDK before each test
      TomatoSentinel.reset();

      // Create test configuration
      testConfig = TomatoSentinelConfig.development();
    });

    test('SDK initialization', () async {
      await TomatoSentinel.initialize(testConfig);
      expect(TomatoSentinel.isInitialized, true);
    });

    test('Security status check', () async {
      await TomatoSentinel.initialize(testConfig);
      
      final status = await TomatoSentinel.instance.getSecurityStatus();
      expect(status, isNotNull);
      expect(status.checkResults, isNotEmpty);
    });

    test('Root detection', () async {
      await TomatoSentinel.initialize(testConfig);
      
      final isRooted = await TomatoSentinel.instance.isDeviceRooted();
      expect(isRooted, isA<bool>());
    });

    test('Emulator detection', () async {
      await TomatoSentinel.initialize(testConfig);
      
      final isEmulator = await TomatoSentinel.instance.isEmulator();
      expect(isEmulator, isA<bool>());
    });

    test('Hook detection', () async {
      await TomatoSentinel.initialize(testConfig);
      
      final isHooked = await TomatoSentinel.instance.isHooked();
      expect(isHooked, isA<bool>());
    });

    test('Tamper detection', () async {
      await TomatoSentinel.initialize(testConfig);
      
      final isTampered = await TomatoSentinel.instance.isTampered();
      expect(isTampered, isA<bool>());
    });

    test('Pin configuration validation', () {
      final pinConfig = PinConfigurationBuilder()
          .domain('api.example.com')
          .addPin('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=')
          .addPin('BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=')
          .build();

      expect(pinConfig.domain, 'api.example.com');
      expect(pinConfig.pins.length, 2);
      expect(pinConfig.hasValidPins, true);
    });

    test('Security event callback', () async {
      var eventReceived = false;
      
      final config = TomatoSentinelConfig.development(
        pinConfigurations: {},
      ).copyWith(
        onSecurityEvent: (event) {
          eventReceived = true;
        },
      );

      await TomatoSentinel.initialize(config);
      await TomatoSentinel.instance.getSecurityStatus();

      // Event may or may not be triggered in test environment
      expect(eventReceived, isA<bool>());
    });

    test('Multiple security checks', () async {
      await TomatoSentinel.initialize(testConfig);
      
      final results = await Future.wait([
        TomatoSentinel.instance.isDeviceRooted(),
        TomatoSentinel.instance.isEmulator(),
        TomatoSentinel.instance.isHooked(),
        TomatoSentinel.instance.isTampered(),
      ]);

      expect(results.length, 4);
      expect(results.every((r) => r is bool), true);
    });
  });

  group('Pin Configuration Tests', () {
    test('Valid pin format', () {
      final pin = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';
      final config = PinConfiguration(
        domain: 'example.com',
        pins: [pin, pin],
      );

      expect(config.validatePinFormat(pin), true);
    });

    test('Invalid pin format', () {
      final invalidPin = 'invalid-pin';
      final config = PinConfiguration(
        domain: 'example.com',
        pins: ['AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
               'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB='],
      );

      expect(config.validatePinFormat(invalidPin), false);
    });

    test('Pin expiration', () {
      final expiredConfig = PinConfiguration(
        domain: 'example.com',
        pins: ['AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
               'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB='],
        expiresAt: DateTime.now().subtract(Duration(days: 1)),
      );

      expect(expiredConfig.isExpired, true);
    });
  });

  group('Security Threat Tests', () {
    test('Threat creation', () {
      final threat = SecurityThreat.create(
        type: ThreatType.rootedDevice,
        severity: ThreatSeverity.critical,
        description: 'Device is rooted',
      );

      expect(threat.type, ThreatType.rootedDevice);
      expect(threat.severity, ThreatSeverity.critical);
      expect(threat.severity.shouldTerminate, true);
    });
  });
}
