#ifndef FLUTTER_PLUGIN_HARDWARE_CRYPTO_PLUGIN_H_
#define FLUTTER_PLUGIN_HARDWARE_CRYPTO_PLUGIN_H_

#include <flutter/method_channel.h>
#include <flutter/plugin_registrar_windows.h>

#include <memory>

namespace hardware_crypto {

class HardwareCryptoPlugin : public flutter::Plugin {
 public:
  static void RegisterWithRegistrar(flutter::PluginRegistrarWindows *registrar);

  HardwareCryptoPlugin();

  virtual ~HardwareCryptoPlugin();

  // Disallow copy and assign.
  HardwareCryptoPlugin(const HardwareCryptoPlugin&) = delete;
  HardwareCryptoPlugin& operator=(const HardwareCryptoPlugin&) = delete;

  // Called when a method is called on this plugin's channel from Dart.
  void HandleMethodCall(
      const flutter::MethodCall<flutter::EncodableValue> &method_call,
      std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result);
};

}  // namespace hardware_crypto

#endif  // FLUTTER_PLUGIN_HARDWARE_CRYPTO_PLUGIN_H_
