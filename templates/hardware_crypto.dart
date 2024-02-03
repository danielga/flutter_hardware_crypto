import 'package:pigeon/pigeon.dart';

@ConfigurePigeon(PigeonOptions(
  cppOptions: CppOptions(namespace: 'hardware_crypto'),
  cppHeaderOut: 'windows/hardware_crypto.g.hpp',
  cppSourceOut: 'windows/hardware_crypto.g.cpp',
  dartPackageName: 'hardware_crypto',
  dartOut: 'lib/hardware_crypto.g.dart',
  dartTestOut: 'test/hardware_crypto_test.g.dart',
  kotlinOptions: KotlinOptions(package: 'xyz.metaman.hardware_crypto'),
  kotlinOut:
      'android/src/main/kotlin/xyz/metaman/hardware_crypto/HardwareCrypto.g.kt',
  swiftOut: 'darwin/Classes/HardwareCrypto.g.swift',
))
@HostApi()
abstract class HardwareCryptoApi {
  bool isSupported();

  @async
  void importPEMKey(String alias, String key);

  @async
  void generateKeyPair(String alias);

  @async
  Uint8List exportPublicKey(String alias);

  @async
  void deleteKeyPair(String alias);

  @async
  Uint8List sign(String alias, Uint8List data);
}
