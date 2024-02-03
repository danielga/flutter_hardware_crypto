#ifndef FLUTTER_PLUGIN_HARDWARE_CRYPTO_PLUGIN_H_
#define FLUTTER_PLUGIN_HARDWARE_CRYPTO_PLUGIN_H_

#include <flutter/method_channel.h>
#include <flutter/plugin_registrar_windows.h>

#include <memory>

#include "hardware_crypto.g.hpp"

namespace hardware_crypto {

class HardwareCryptoPlugin : public flutter::Plugin, public HardwareCryptoApi {
 public:
  static void RegisterWithRegistrar(flutter::PluginRegistrarWindows *registrar);

  HardwareCryptoPlugin();

  virtual ~HardwareCryptoPlugin();

  // Disallow copy and assign.
  HardwareCryptoPlugin(const HardwareCryptoPlugin&) = delete;
  HardwareCryptoPlugin& operator=(const HardwareCryptoPlugin&) = delete;

  ErrorOr<bool> IsSupported();
  void ImportPEMKey(
      const std::string& alias,
      const std::string& key,
      std::function<void(std::optional<FlutterError> reply)> result);
  void GenerateKeyPair(
      const std::string& alias,
      std::function<void(std::optional<FlutterError> reply)> result);
  void ExportPublicKey(
      const std::string& alias,
      std::function<void(ErrorOr<std::vector<uint8_t>> reply)> result);
  void DeleteKeyPair(
      const std::string& alias,
      std::function<void(std::optional<FlutterError> reply)> result);
  void Sign(
      const std::string& alias,
      const std::vector<uint8_t>& data,
      std::function<void(ErrorOr<std::vector<uint8_t>> reply)> result);
};

}  // namespace hardware_crypto

#endif  // FLUTTER_PLUGIN_HARDWARE_CRYPTO_PLUGIN_H_
