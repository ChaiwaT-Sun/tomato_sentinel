// Copyright (c) 2026 Tomato Sentinel
// Unit tests: SecurityCheckResult and SecurityStatus

import 'package:flutter_test/flutter_test.dart';
import 'package:tomato_sentinel/tomato_sentinel.dart';

void main() {
  SecurityThreat makeThreat(ThreatSeverity severity) {
    return SecurityThreat.create(
      type: ThreatType.rootedDevice,
      severity: severity,
      description: 'Test threat',
    );
  }

  group('SecurityCheckResult', () {
    test('secure() factory creates secure result with no threats', () {
      final result = SecurityCheckResult.secure('root');

      expect(result.isSecure, isTrue);
      expect(result.threats, isEmpty);
      expect(result.checkType, 'root');
      expect(result.checkedAt, isA<DateTime>());
    });

    test('insecure() factory creates insecure result with threats', () {
      final threat = makeThreat(ThreatSeverity.critical);
      final result = SecurityCheckResult.insecure(
        checkType: 'root',
        threats: [threat],
      );

      expect(result.isSecure, isFalse);
      expect(result.threats.length, 1);
      expect(result.checkType, 'root');
    });

    test('hasCriticalThreats returns true when critical threat present', () {
      final result = SecurityCheckResult.insecure(
        checkType: 'hook',
        threats: [makeThreat(ThreatSeverity.critical)],
      );

      expect(result.hasCriticalThreats, isTrue);
    });

    test('hasCriticalThreats returns false when no critical threats', () {
      final result = SecurityCheckResult.insecure(
        checkType: 'emulator',
        threats: [makeThreat(ThreatSeverity.high)],
      );

      expect(result.hasCriticalThreats, isFalse);
    });

    test('hasHighThreats returns true for high and critical', () {
      final highResult = SecurityCheckResult.insecure(
        checkType: 'emulator',
        threats: [makeThreat(ThreatSeverity.high)],
      );
      final criticalResult = SecurityCheckResult.insecure(
        checkType: 'root',
        threats: [makeThreat(ThreatSeverity.critical)],
      );

      expect(highResult.hasHighThreats, isTrue);
      expect(criticalResult.hasHighThreats, isTrue);
    });

    test('hasHighThreats returns false for medium and below', () {
      final result = SecurityCheckResult.insecure(
        checkType: 'tamper',
        threats: [makeThreat(ThreatSeverity.medium)],
      );

      expect(result.hasHighThreats, isFalse);
    });

    test('maxSeverity returns info when no threats', () {
      final result = SecurityCheckResult.secure('root');
      expect(result.maxSeverity, ThreatSeverity.info);
    });

    test('maxSeverity returns highest severity', () {
      final result = SecurityCheckResult.insecure(
        checkType: 'multi',
        threats: [
          makeThreat(ThreatSeverity.low),
          makeThreat(ThreatSeverity.critical),
          makeThreat(ThreatSeverity.medium),
        ],
      );

      expect(result.maxSeverity, ThreatSeverity.critical);
    });

    test('toString contains isSecure and checkType', () {
      final result = SecurityCheckResult.secure('root');
      expect(result.toString(), contains('isSecure: true'));
      expect(result.toString(), contains('root'));
    });
  });

  group('SecurityStatus', () {
    test('initial() creates secure status with no checks', () {
      final status = SecurityStatus.initial();

      expect(status.isDeviceSecure, isTrue);
      expect(status.checkResults, isEmpty);
      expect(status.allThreats, isEmpty);
    });

    test('allThreats aggregates threats from all checks', () {
      final status = SecurityStatus(
        isDeviceSecure: false,
        checkResults: {
          'root': SecurityCheckResult.insecure(
            checkType: 'root',
            threats: [makeThreat(ThreatSeverity.critical)],
          ),
          'emulator': SecurityCheckResult.insecure(
            checkType: 'emulator',
            threats: [makeThreat(ThreatSeverity.high)],
          ),
          'hook': SecurityCheckResult.secure('hook'),
        },
        lastChecked: DateTime.now(),
      );

      expect(status.allThreats.length, 2);
    });

    test('hasCriticalThreats returns true when any check has critical threat', () {
      final status = SecurityStatus(
        isDeviceSecure: false,
        checkResults: {
          'root': SecurityCheckResult.insecure(
            checkType: 'root',
            threats: [makeThreat(ThreatSeverity.critical)],
          ),
        },
        lastChecked: DateTime.now(),
      );

      expect(status.hasCriticalThreats, isTrue);
    });

    test('hasCriticalThreats returns false when no critical threats', () {
      final status = SecurityStatus(
        isDeviceSecure: false,
        checkResults: {
          'emulator': SecurityCheckResult.insecure(
            checkType: 'emulator',
            threats: [makeThreat(ThreatSeverity.high)],
          ),
        },
        lastChecked: DateTime.now(),
      );

      expect(status.hasCriticalThreats, isFalse);
    });

    test('copyWith creates modified copy', () {
      final original = SecurityStatus.initial();
      final copy = original.copyWith(isDeviceSecure: false);

      expect(copy.isDeviceSecure, isFalse);
      expect(copy.checkResults, original.checkResults);
    });
  });
}
