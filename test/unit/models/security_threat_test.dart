// Copyright (c) 2026 Tomato Sentinel
// Unit tests: SecurityThreat model

import 'package:flutter_test/flutter_test.dart';
import 'package:tomato_sentinel/tomato_sentinel.dart';

void main() {
  group('SecurityThreat', () {
    test('create() sets all fields correctly', () {
      final threat = SecurityThreat.create(
        type: ThreatType.rootedDevice,
        severity: ThreatSeverity.critical,
        description: 'Device is rooted',
        details: {'method': 'su_binary'},
      );

      expect(threat.type, ThreatType.rootedDevice);
      expect(threat.severity, ThreatSeverity.critical);
      expect(threat.description, 'Device is rooted');
      expect(threat.details['method'], 'su_binary');
      expect(threat.detectedAt, isA<DateTime>());
    });

    test('create() uses empty map when details not provided', () {
      final threat = SecurityThreat.create(
        type: ThreatType.emulatorDetected,
        severity: ThreatSeverity.high,
        description: 'Emulator detected',
      );

      expect(threat.details, isEmpty);
    });

    test('detectedAt is close to now', () {
      final before = DateTime.now();
      final threat = SecurityThreat.create(
        type: ThreatType.hookingFrameworkDetected,
        severity: ThreatSeverity.critical,
        description: 'Frida detected',
      );
      final after = DateTime.now();

      expect(
        threat.detectedAt.isAfter(before.subtract(const Duration(seconds: 1))),
        isTrue,
      );
      expect(threat.detectedAt.isBefore(after.add(const Duration(seconds: 1))), isTrue);
    });

    test('equality based on type, severity, description', () {
      final t1 = SecurityThreat.create(
        type: ThreatType.rootedDevice,
        severity: ThreatSeverity.critical,
        description: 'Rooted',
      );
      final t2 = SecurityThreat.create(
        type: ThreatType.rootedDevice,
        severity: ThreatSeverity.critical,
        description: 'Rooted',
      );
      final t3 = SecurityThreat.create(
        type: ThreatType.emulatorDetected,
        severity: ThreatSeverity.high,
        description: 'Emulator',
      );

      expect(t1, equals(t2));
      expect(t1, isNot(equals(t3)));
    });

    test('toString contains type and severity', () {
      final threat = SecurityThreat.create(
        type: ThreatType.sslPinningViolation,
        severity: ThreatSeverity.critical,
        description: 'Pin mismatch',
      );

      expect(threat.toString(), contains('sslPinningViolation'));
      expect(threat.toString(), contains('critical'));
    });
  });

  group('ThreatSeverity extensions', () {
    test('critical shouldTerminate is true', () {
      expect(ThreatSeverity.critical.shouldTerminate, isTrue);
    });

    test('high shouldTerminate is false', () {
      expect(ThreatSeverity.high.shouldTerminate, isFalse);
    });

    test('high shouldRestrict is true', () {
      expect(ThreatSeverity.high.shouldRestrict, isTrue);
    });

    test('medium shouldRestrict is false', () {
      expect(ThreatSeverity.medium.shouldRestrict, isFalse);
    });

    test('medium shouldWarn is true', () {
      expect(ThreatSeverity.medium.shouldWarn, isTrue);
    });

    test('low shouldWarn is false', () {
      expect(ThreatSeverity.low.shouldWarn, isFalse);
    });

    test('info shouldTerminate is false', () {
      expect(ThreatSeverity.info.shouldTerminate, isFalse);
    });

    test('all ThreatType values are defined', () {
      expect(ThreatType.values.length, greaterThanOrEqualTo(7));
      expect(ThreatType.values, contains(ThreatType.rootedDevice));
      expect(ThreatType.values, contains(ThreatType.emulatorDetected));
      expect(ThreatType.values, contains(ThreatType.hookingFrameworkDetected));
      expect(ThreatType.values, contains(ThreatType.tamperingDetected));
      expect(ThreatType.values, contains(ThreatType.sslPinningViolation));
      expect(ThreatType.values, contains(ThreatType.debuggerDetected));
      expect(ThreatType.values, contains(ThreatType.integrityCheckFailed));
    });
  });
}
