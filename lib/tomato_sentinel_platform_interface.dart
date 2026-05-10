// Copyright (c) 2026 Tomato Sentinel
// Platform interface (kept for compatibility)

import 'package:plugin_platform_interface/plugin_platform_interface.dart';
import 'src/platform/method_channel_tomato_sentinel.dart';

abstract class TomatoSentinelPlatform extends PlatformInterface {
  TomatoSentinelPlatform() : super(token: _token);

  static final Object _token = Object();

  static TomatoSentinelPlatform _instance = MethodChannelTomatoSentinelPlatform();

  static TomatoSentinelPlatform get instance => _instance;

  static set instance(TomatoSentinelPlatform instance) {
    PlatformInterface.verifyToken(instance, _token);
    _instance = instance;
  }

  Future<String?> getPlatformVersion() {
    throw UnimplementedError('getPlatformVersion() has not been implemented.');
  }
}

class MethodChannelTomatoSentinelPlatform extends TomatoSentinelPlatform {
  final MethodChannelTomatoSentinel _methodChannel = MethodChannelTomatoSentinel();

  @override
  Future<String?> getPlatformVersion() async {
    return await _methodChannel.getPlatformVersion();
  }
}
