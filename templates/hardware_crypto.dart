import 'package:pigeon/pigeon.dart';

class Version {
  String? string;
}

@ConfigurePigeon(PigeonOptions(
  dartOut: 'lib/hardware_crypto.g.dart',
  dartTestOut: 'test/hardware_crypto_test.g.dart',
  kotlinOut: 'android/src/main/kotlin/xyz/metaman/hardware_crypto/HardwareCrypto.g.kt',
  kotlinOptions: KotlinOptions(package: 'xyz.metaman.hardware_crypto'),
  swiftOut: 'darwin/Classes/HardwareCrypto.g.swift',
  dartPackageName: 'hardware_crypto',
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
