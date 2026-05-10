// Copyright (c) 2026 Tomato Sentinel
// Unit tests: TomatoSentinel SDK lifecycle and security checks

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:tomato_sentinel/tomato_sentinel.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  const MethodChannel channel = MethodChannel('tomato_sentinel');

  const validPin1 = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';
  const validPin2 = 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=';

  // Default mock: clean device
  void setupCleanDeviceMock() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (MethodCall call) async {
      switch (call.method) {
        case 'isDeviceRooted':
          return false;
        case 'isEmulator':
          return false;
        case 'isHooked':
          return false;
        case 'isTampered':
          return false;
        case 'checkIntegrity':
          return {
            'isValid': true,
            'meetsDeviceIntegrity': true,
            'meetsBasicIntegrity': true,
            'meetsStrongIntegrity': false,
          };
        case 'getPlatformVersion':
          return 'Android 14';
        default:
          return null;
      }
    });
  }

  // Mock: compromised device
  void setupCompromisedDeviceMock({
    bool rooted = false,
    bool emulator = false,
    bool hooked = false,
    bool tampered = false,
  }) {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (MethodCall call) async {
      switch (call.method) {
        case 'isDeviceRooted':
          return rooted;
        case 'isEmulator':
          return emulator;
        case 'isHooked':
          return hooked;
        case 'isTampered':
          return tampered;
        case 'checkIntegrity':
          return {'isValid': true, 'meetsDeviceIntegrity': true, 'meetsBasicIntegrity': true};
        default:
          return null;
      }
    });
  }

  setUp(() {
    TomatoSentinel.reset();
    setupCleanDeviceMock();
  });

  tearDown(() {
    TomatoSentinel.reset();
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, null);
  });

  group('TomatoSentinel lifecycle', () {
    test('isInitialized is false before initialize()', () {
      expect(TomatoSentinel.isInitialized, isFalse);
    });

    test('instance throws SecurityException before initialize()', () {
      expect(
        () => TomatoSentinel.instance,
        throwsA(isA<SecurityException>()),
      );
    });

    test('initialize() with development config succeeds', () async {
      await TomatoSentinel.initialize(TomatoSentinelConfig.development());

      expect(TomatoSentinel.isInitialized, isTrue);
      expect(TomatoSentinel.config, isNotNull);
    });

    test('initialize() twice does not throw', () async {
      await TomatoSentinel.initialize(TomatoSentinelConfig.development());
      await TomatoSentinel.initialize(TomatoSentinelConfig.development());

      expect(TomatoSentinel.isInitialized, isTrue);
    });

    test('instance returns singleton after initialize()', () async {
      await TomatoSentinel.initialize(TomatoSentinelConfig.development());

      final a = TomatoSentinel.instance;
      final b = TomatoSentinel.instance;

      expect(identical(a, b), isTrue);
    });

    test('dispose() resets SDK state', () async {
      await TomatoSentinel.initialize(TomatoSentinelConfig.development());
      await TomatoSentinel.dispose();

      expect(TomatoSentinel.isInitialized, isFalse);
      expect(TomatoSentinel.config, isNull);
    });

    test('reset() clears instance (test helper)', () async {
      await TomatoSentinel.initialize(TomatoSentinelConfig.development());
      TomatoSentinel.reset();

      expect(TomatoSentinel.isInitialized, isFalse);
    });
  });

  group('Security checks on clean device', () {
    setUp(() async {
      await TomatoSentinel.initialize(TomatoSentinelConfig(
        pinConfigurations: {},
        enableRootDetection: true,
        enableEmulatorDetection: true,
        enableHookDetection: true,
        enableTamperDetection: true,
        enableIntegrityCheck: false, // skip integrity (needs platform setup)
        failClosed: false,
      ));
    });

    test('isDeviceRooted() returns false on clean device', () async {
      expect(await TomatoSentinel.instance.isDeviceRooted(), isFalse);
    });

    test('isEmulator() returns false on clean device', () async {
      expect(await TomatoSentinel.instance.isEmulator(), isFalse);
    });

    test('isHooked() returns false on clean device', () async {
      expect(await TomatoSentinel.instance.isHooked(), isFalse);
    });

    test('isTampered() returns false on clean device', () async {
      expect(await TomatoSentinel.instance.isTampered(), isFalse);
    });

    test('getSecurityStatus() returns secure status', () async {
      final status = await TomatoSentinel.instance.getSecurityStatus();

      expect(status.isDeviceSecure, isTrue);
      expect(status.allThreats, isEmpty);
    });
  });

  group('Security checks on rooted device', () {
    setUp(() async {
      setupCompromisedDeviceMock(rooted: true);
      await TomatoSentinel.initialize(TomatoSentinelConfig(
        pinConfigurations: {},
        enableRootDetection: true,
        enableEmulatorDetection: false,
        enableHookDetection: false,
        enableTamperDetection: false,
        enableIntegrityCheck: false,
        failClosed: false,
      ));
    });

    test('isDeviceRooted() returns true', () async {
      expect(await TomatoSentinel.instance.isDeviceRooted(), isTrue);
    });

    test('getSecurityStatus() returns insecure with root threat', () async {
      final status = await TomatoSentinel.instance.getSecurityStatus();

      expect(status.isDeviceSecure, isFalse);
      expect(
        status.allThreats.any((t) => t.type == ThreatType.rootedDevice),
        isTrue,
      );
    });

    test('root threat has critical severity', () async {
      final status = await TomatoSentinel.instance.getSecurityStatus();
      final rootThreat = status.allThreats
          .firstWhere((t) => t.type == ThreatType.rootedDevice);

      expect(rootThreat.severity, ThreatSeverity.critical);
    });
  });

  group('Security checks on emulator', () {
    setUp(() async {
      setupCompromisedDeviceMock(emulator: true);
      await TomatoSentinel.initialize(TomatoSentinelConfig(
        pinConfigurations: {},
        enableRootDetection: false,
        enableEmulatorDetection: true,
        enableHookDetection: false,
        enableTamperDetection: false,
        enableIntegrityCheck: false,
        failClosed: false,
      ));
    });

    test('isEmulator() returns true', () async {
      expect(await TomatoSentinel.instance.isEmulator(), isTrue);
    });

    test('emulator threat has high severity', () async {
      final status = await TomatoSentinel.instance.getSecurityStatus();
      final emulatorThreat = status.allThreats
          .firstWhere((t) => t.type == ThreatType.emulatorDetected);

      expect(emulatorThreat.severity, ThreatSeverity.high);
    });
  });

  group('Security checks with hooked device', () {
    setUp(() async {
      setupCompromisedDeviceMock(hooked: true);
      await TomatoSentinel.initialize(TomatoSentinelConfig(
        pinConfigurations: {},
        enableRootDetection: false,
        enableEmulatorDetection: false,
        enableHookDetection: true,
        enableTamperDetection: false,
        enableIntegrityCheck: false,
        failClosed: false,
      ));
    });

    test('isHooked() returns true', () async {
      expect(await TomatoSentinel.instance.isHooked(), isTrue);
    });

    test('hook threat has critical severity', () async {
      final status = await TomatoSentinel.instance.getSecurityStatus();
      final hookThreat = status.allThreats
          .firstWhere((t) => t.type == ThreatType.hookingFrameworkDetected);

      expect(hookThreat.severity, ThreatSeverity.critical);
    });
  });

  group('Security checks with tampered app', () {
    setUp(() async {
      setupCompromisedDeviceMock(tampered: true);
      await TomatoSentinel.initialize(TomatoSentinelConfig(
        pinConfigurations: {},
        enableRootDetection: false,
        enableEmulatorDetection: false,
        enableHookDetection: false,
        enableTamperDetection: true,
        enableIntegrityCheck: false,
        failClosed: false,
      ));
    });

    test('isTampered() returns true', () async {
      expect(await TomatoSentinel.instance.isTampered(), isTrue);
    });

    test('tamper threat has critical severity', () async {
      final status = await TomatoSentinel.instance.getSecurityStatus();
      final tamperThreat = status.allThreats
          .firstWhere((t) => t.type == ThreatType.tamperingDetected);

      expect(tamperThreat.severity, ThreatSeverity.critical);
    });
  });

  group('failClosed behavior', () {
    test('failClosed=true: platform error treated as threat', () async {
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (MethodCall call) async {
        if (call.method == 'isDeviceRooted') {
          throw PlatformException(code: 'ERROR', message: 'Native crash');
        }
        return false;
      });

      await TomatoSentinel.initialize(TomatoSentinelConfig(
        pinConfigurations: {},
        enableRootDetection: true,
        enableEmulatorDetection: false,
        enableHookDetection: false,
        enableTamperDetection: false,
        enableIntegrityCheck: false,
        failClosed: true,
      ));

      final status = await TomatoSentinel.instance.getSecurityStatus();
      // failClosed: error in check = insecure
      expect(status.isDeviceSecure, isFalse);
    });

    test('failClosed=false: platform error treated as secure', () async {
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (MethodCall call) async {
        if (call.method == 'isDeviceRooted') {
          throw PlatformException(code: 'ERROR', message: 'Native crash');
        }
        return false;
      });

      await TomatoSentinel.initialize(TomatoSentinelConfig(
        pinConfigurations: {},
        enableRootDetection: true,
        enableEmulatorDetection: false,
        enableHookDetection: false,
        enableTamperDetection: false,
        enableIntegrityCheck: false,
        failClosed: false,
      ));

      final status = await TomatoSentinel.instance.getSecurityStatus();
      // failClosed=false: error in check = pass through
      expect(status.checkResults['root']?.isSecure, isTrue);
    });
  });

  group('Security event callback', () {
    test('onSecurityEvent is called when threat detected', () async {
      setupCompromisedDeviceMock(rooted: true);

      final events = <SecurityEvent>[];
      await TomatoSentinel.initialize(TomatoSentinelConfig(
        pinConfigurations: {},
        enableRootDetection: true,
        enableEmulatorDetection: false,
        enableHookDetection: false,
        enableTamperDetection: false,
        enableIntegrityCheck: false,
        failClosed: false,
        onSecurityEvent: events.add,
      ));

      await TomatoSentinel.instance.getSecurityStatus();

      expect(events, isNotEmpty);
      expect(
        events.any((e) => e.type == SecurityEventType.rootDetected),
        isTrue,
      );
    });
  });

  group('performCheck() specific checks', () {
    setUp(() async {
      await TomatoSentinel.initialize(TomatoSentinelConfig(
        pinConfigurations: {},
        enableRootDetection: true,
        enableEmulatorDetection: true,
        enableHookDetection: true,
        enableTamperDetection: true,
        enableIntegrityCheck: false,
        failClosed: false,
      ));
    });

    test('performCheck(rootDetection) returns secure result', () async {
      final result = await TomatoSentinel.instance
          .performCheck(SecurityCheckType.rootDetection);

      expect(result.isSecure, isTrue);
      expect(result.checkType, 'root');
    });

    test('performCheck(emulatorDetection) returns secure result', () async {
      final result = await TomatoSentinel.instance
          .performCheck(SecurityCheckType.emulatorDetection);

      expect(result.isSecure, isTrue);
    });

    test('performCheck(all) aggregates all checks', () async {
      final result = await TomatoSentinel.instance
          .performCheck(SecurityCheckType.all);

      expect(result.isSecure, isTrue);
      expect(result.checkType, 'all');
    });
  });
}
