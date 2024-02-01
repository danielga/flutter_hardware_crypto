import 'package:flutter_test/flutter_test.dart';
import 'package:hardware_crypto/hardware_crypto.dart';
import 'package:hardware_crypto/hardware_crypto_platform_interface.dart';
import 'package:hardware_crypto/hardware_crypto_method_channel.dart';
import 'package:plugin_platform_interface/plugin_platform_interface.dart';

class MockHardwareCryptoPlatform
    with MockPlatformInterfaceMixin
    implements HardwareCryptoPlatform {

  @override
  Future<String?> getPlatformVersion() => Future.value('42');
}

void main() {
  final HardwareCryptoPlatform initialPlatform = HardwareCryptoPlatform.instance;

  test('$MethodChannelHardwareCrypto is the default instance', () {
    expect(initialPlatform, isInstanceOf<MethodChannelHardwareCrypto>());
  });

  test('getPlatformVersion', () async {
    HardwareCrypto hardwareCryptoPlugin = HardwareCrypto();
    MockHardwareCryptoPlatform fakePlatform = MockHardwareCryptoPlatform();
    HardwareCryptoPlatform.instance = fakePlatform;

    expect(await hardwareCryptoPlugin.getPlatformVersion(), '42');
  });
}
