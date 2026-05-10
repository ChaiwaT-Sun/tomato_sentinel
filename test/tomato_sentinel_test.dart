import 'package:flutter_test/flutter_test.dart';
import 'package:tomato_sentinel/tomato_sentinel.dart';
import 'package:tomato_sentinel/tomato_sentinel_platform_interface.dart';
import 'package:tomato_sentinel/tomato_sentinel_method_channel.dart';
import 'package:plugin_platform_interface/plugin_platform_interface.dart';

class MockTomatoSentinelPlatform
    with MockPlatformInterfaceMixin
    implements TomatoSentinelPlatform {

  @override
  Future<String?> getPlatformVersion() => Future.value('42');
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  final TomatoSentinelPlatform initialPlatform = TomatoSentinelPlatform.instance;

  setUp(() {
    // Reset SDK before each test
    TomatoSentinel.reset();
  });

  test('$MethodChannelTomatoSentinel is the default instance', () {
    expect(initialPlatform, isInstanceOf<MethodChannelTomatoSentinel>());
  });

  test('getPlatformVersion', () async {
    MockTomatoSentinelPlatform fakePlatform = MockTomatoSentinelPlatform();
    TomatoSentinelPlatform.instance = fakePlatform;

    expect(await fakePlatform.getPlatformVersion(), '42');
  });

  group('TomatoSentinel SDK', () {
    test('initialization with development config', () async {
      final config = TomatoSentinelConfig.development();
      await TomatoSentinel.initialize(config);
      
      expect(TomatoSentinel.isInitialized, true);
      expect(TomatoSentinel.config, isNotNull);
    });

    test('throws exception when accessing instance before initialization', () {
      expect(
        () => TomatoSentinel.instance,
        throwsA(isA<SecurityException>()),
      );
    });

    test('pin configuration validation', () {
      final pinConfig = PinConfigurationBuilder()
          .domain('api.example.com')
          .addPin('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=')
          .addPin('BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=')
          .build();

      expect(pinConfig.domain, 'api.example.com');
      expect(pinConfig.pins.length, 2);
      expect(pinConfig.hasValidPins, true);
    });

    test('pin format validation', () {
      final validPin = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';
      final invalidPin = 'invalid-pin';
      
      final config = PinConfiguration(
        domain: 'example.com',
        pins: [validPin, validPin],
      );

      expect(config.validatePinFormat(validPin), true);
      expect(config.validatePinFormat(invalidPin), false);
    });

    test('security threat creation', () {
      final threat = SecurityThreat.create(
        type: ThreatType.rootedDevice,
        severity: ThreatSeverity.critical,
        description: 'Device is rooted',
      );

      expect(threat.type, ThreatType.rootedDevice);
      expect(threat.severity, ThreatSeverity.critical);
      expect(threat.description, 'Device is rooted');
      expect(threat.detectedAt, isA<DateTime>());
    });

    test('threat severity levels', () {
      expect(ThreatSeverity.critical.shouldTerminate, true);
      expect(ThreatSeverity.high.shouldRestrict, true);
      expect(ThreatSeverity.medium.shouldWarn, true);
      expect(ThreatSeverity.low.shouldTerminate, false);
    });

    test('development config has relaxed security', () {
      final config = TomatoSentinelConfig.development();

      expect(config.enableRootDetection, false);
      expect(config.enableEmulatorDetection, false);
      expect(config.enableHookDetection, false);
      expect(config.failClosed, false);
    });

    test('production config requires pins', () {
      expect(
        () => TomatoSentinelConfig.production(
          pinConfigurations: {},
          remoteConfigUrl: 'https://example.com',
          remoteConfigPublicKey: 'key',
        ),
        throwsA(isA<AssertionError>()),
      );
    });
  });

  group('Security Exceptions', () {
    test('SecurityException formatting', () {
      final exception = SecurityException('Test error');
      expect(exception.toString(), contains('SecurityException: Test error'));
    });

    test('SSLPinningException includes domain', () {
      final exception = SSLPinningException(
        'Pin mismatch',
        domain: 'api.example.com',
      );
      expect(exception.toString(), contains('api.example.com'));
      expect(exception.toString(), contains('Pin mismatch'));
    });
  });
}
