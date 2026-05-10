import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import 'tomato_sentinel_platform_interface.dart';

/// An implementation of [TomatoSentinelPlatform] that uses method channels.
class MethodChannelTomatoSentinel extends TomatoSentinelPlatform {
  /// The method channel used to interact with the native platform.
  @visibleForTesting
  final methodChannel = const MethodChannel('tomato_sentinel');

  @override
  Future<String?> getPlatformVersion() async {
    final version = await methodChannel.invokeMethod<String>('getPlatformVersion');
    return version;
  }
}
