// Copyright (c) 2026 Tomato Sentinel
// Unit tests: RemoteConfig model

import 'package:flutter_test/flutter_test.dart';
import 'package:tomato_sentinel/tomato_sentinel.dart';

void main() {
  const validPin1 = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';
  const validPin2 = 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=';

  RemoteConfig buildConfig({
    int version = 1,
    DateTime? createdAt,
    DateTime? expiresAt,
    String signature = 'dGVzdHNpZ25hdHVyZQ==',
    String nonce = 'test-nonce-12345',
  }) {
    final now = DateTime.now();
    return RemoteConfig(
      version: version,
      createdAt: createdAt ?? now.subtract(const Duration(hours: 1)),
      expiresAt: expiresAt ?? now.add(const Duration(days: 30)),
      pinConfigurations: {
        'api.example.com': PinConfiguration(
          domain: 'api.example.com',
          pins: [validPin1, validPin2],
        ),
      },
      signature: signature,
      nonce: nonce,
    );
  }

  group('RemoteConfig', () {
    test('isValid returns true for valid config', () {
      final config = buildConfig();
      expect(config.isValid, isTrue);
    });

    test('isExpired returns true when past expiry', () {
      final config = buildConfig(
        expiresAt: DateTime.now().subtract(const Duration(hours: 1)),
      );
      expect(config.isExpired, isTrue);
      expect(config.isValid, isFalse);
    });

    test('isNotYetValid returns true when future createdAt', () {
      final config = buildConfig(
        createdAt: DateTime.now().add(const Duration(hours: 1)),
      );
      expect(config.isNotYetValid, isTrue);
      expect(config.isValid, isFalse);
    });

    test('getSignaturePayload includes version, dates, and nonce', () {
      final config = buildConfig(version: 5, nonce: 'unique-nonce');
      final payload = config.getSignaturePayload();

      expect(payload, contains('5'));
      expect(payload, contains('unique-nonce'));
    });

    test('toJson and fromJson round-trip', () {
      final original = buildConfig(version: 3);
      final json = original.toJson();
      final restored = RemoteConfig.fromJson(json);

      expect(restored.version, original.version);
      expect(restored.signature, original.signature);
      expect(restored.nonce, original.nonce);
      expect(restored.pinConfigurations.keys, original.pinConfigurations.keys);
    });

    test('fromJson parses security policy', () {
      final config = RemoteConfig(
        version: 1,
        createdAt: DateTime.now().subtract(const Duration(hours: 1)),
        expiresAt: DateTime.now().add(const Duration(days: 30)),
        pinConfigurations: {
          'api.example.com': PinConfiguration(
            domain: 'api.example.com',
            pins: [validPin1, validPin2],
          ),
        },
        securityPolicy: const SecurityPolicy(
          enforceRootDetection: true,
          enforceEmulatorDetection: true,
          enforceHookDetection: true,
          enforceTamperDetection: true,
          minimumAppVersion: 2,
          blockedVersions: ['1.0.0', '1.0.1'],
        ),
        signature: 'dGVzdA==',
        nonce: 'nonce',
      );

      final json = config.toJson();
      final restored = RemoteConfig.fromJson(json);

      expect(restored.securityPolicy, isNotNull);
      expect(restored.securityPolicy!.enforceRootDetection, isTrue);
      expect(restored.securityPolicy!.minimumAppVersion, 2);
      expect(restored.securityPolicy!.blockedVersions, contains('1.0.0'));
    });
  });

  group('SecurityPolicy', () {
    test('toJson and fromJson round-trip', () {
      const policy = SecurityPolicy(
        enforceRootDetection: true,
        enforceEmulatorDetection: false,
        enforceHookDetection: true,
        enforceTamperDetection: true,
        minimumAppVersion: 5,
        blockedVersions: ['1.0', '2.0'],
      );

      final json = policy.toJson();
      final restored = SecurityPolicy.fromJson(json);

      expect(restored.enforceRootDetection, policy.enforceRootDetection);
      expect(restored.enforceEmulatorDetection, policy.enforceEmulatorDetection);
      expect(restored.minimumAppVersion, policy.minimumAppVersion);
      expect(restored.blockedVersions, policy.blockedVersions);
    });

    test('blockedVersions defaults to empty list', () {
      final json = {
        'enforceRootDetection': true,
        'enforceEmulatorDetection': true,
        'enforceHookDetection': true,
        'enforceTamperDetection': true,
        'minimumAppVersion': 1,
      };

      final policy = SecurityPolicy.fromJson(json);
      expect(policy.blockedVersions, isEmpty);
    });
  });
}
