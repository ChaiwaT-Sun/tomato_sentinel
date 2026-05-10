// Copyright (c) 2026 Tomato Sentinel
// Unit tests: Security exceptions

import 'package:flutter_test/flutter_test.dart';
import 'package:tomato_sentinel/tomato_sentinel.dart';

void main() {
  group('SecurityException', () {
    test('toString includes class name and message', () {
      final e = SecurityException('Something went wrong');
      expect(e.toString(), contains('SecurityException'));
      expect(e.toString(), contains('Something went wrong'));
    });

    test('toString includes cause when provided', () {
      final cause = Exception('root cause');
      final e = SecurityException('Wrapper error', cause);
      expect(e.toString(), contains('Wrapper error'));
      expect(e.toString(), contains('Caused by'));
    });

    test('toString without cause has no Caused by', () {
      final e = SecurityException('Simple error');
      expect(e.toString(), isNot(contains('Caused by')));
    });

    test('implements Exception', () {
      final e = SecurityException('test');
      expect(e, isA<Exception>());
    });
  });

  group('SSLPinningException', () {
    test('toString includes domain and message', () {
      final e = SSLPinningException(
        'Pin mismatch',
        domain: 'api.example.com',
      );
      expect(e.toString(), contains('api.example.com'));
      expect(e.toString(), contains('Pin mismatch'));
      expect(e.toString(), contains('SSLPinningException'));
    });

    test('stores domain field', () {
      final e = SSLPinningException('error', domain: 'test.com');
      expect(e.domain, 'test.com');
    });

    test('is a SecurityException', () {
      final e = SSLPinningException('error', domain: 'test.com');
      expect(e, isA<SecurityException>());
    });
  });

  group('RootDetectionException', () {
    test('is a SecurityException', () {
      final e = RootDetectionException('Rooted device');
      expect(e, isA<SecurityException>());
    });

    test('toString contains message', () {
      final e = RootDetectionException('Rooted device');
      expect(e.toString(), contains('Rooted device'));
    });
  });

  group('EmulatorDetectionException', () {
    test('is a SecurityException', () {
      final e = EmulatorDetectionException('Emulator detected');
      expect(e, isA<SecurityException>());
    });
  });

  group('HookDetectionException', () {
    test('is a SecurityException', () {
      final e = HookDetectionException('Frida detected');
      expect(e, isA<SecurityException>());
    });
  });

  group('TamperDetectionException', () {
    test('is a SecurityException', () {
      final e = TamperDetectionException('App tampered');
      expect(e, isA<SecurityException>());
    });
  });

  group('IntegrityCheckException', () {
    test('is a SecurityException', () {
      final e = IntegrityCheckException('Integrity failed');
      expect(e, isA<SecurityException>());
    });
  });

  group('RemoteConfigException', () {
    test('is a SecurityException', () {
      final e = RemoteConfigException('Config fetch failed');
      expect(e, isA<SecurityException>());
    });
  });
}
