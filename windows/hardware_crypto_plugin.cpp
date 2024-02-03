#include "hardware_crypto_plugin.hpp"

#include <hardware_crypto.hpp>

// This must be included before many other Windows headers.
#include <windows.h>

// For getPlatformVersion; remove unless needed for your plugin implementation.
#include <VersionHelpers.h>

#include <flutter/method_channel.h>
#include <flutter/plugin_registrar_windows.h>
#include <flutter/standard_method_codec.h>

#include <memory>
#include <sstream>

namespace hardware_crypto
{

// static
void HardwareCryptoPlugin::RegisterWithRegistrar(
    flutter::PluginRegistrarWindows *registrar) {
  auto plugin = std::make_unique<HardwareCryptoPlugin>();
  SetUp(registrar->messenger(), plugin.get());
  registrar->AddPlugin(std::move(plugin));
}

HardwareCryptoPlugin::HardwareCryptoPlugin() {}

HardwareCryptoPlugin::~HardwareCryptoPlugin() {}

ErrorOr<bool> HardwareCryptoPlugin::IsSupported() {
  return ErrorOr(true);
}

void HardwareCryptoPlugin::ImportPEMKey(
    const std::string& alias,
    const std::string& key,
    std::function<void(std::optional<FlutterError> reply)> result) {
    const auto private_key = hardware_crypto::import_private_key(key);
    hardware_crypto::save_private_key(private_key, alias);
    result(std::nullopt);
}

void HardwareCryptoPlugin::GenerateKeyPair(
    const std::string& alias,
    std::function<void(std::optional<FlutterError> reply)> result) {
    const auto private_key = hardware_crypto::generate_private_key();
    hardware_crypto::save_private_key(private_key, alias);
    result(std::nullopt);
}

void HardwareCryptoPlugin::ExportPublicKey(
    const std::string& alias,
    std::function<void(ErrorOr<std::vector<uint8_t>> reply)> result) {
    const auto private_key = hardware_crypto::load_private_key(alias);
    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey public_key;
    private_key.MakePublicKey(public_key);
    const auto public_key_data = hardware_crypto::export_public_key(public_key);
    result(public_key_data);
}

void HardwareCryptoPlugin::DeleteKeyPair(
    const std::string& alias,
    std::function<void(std::optional<FlutterError> reply)> result) {
    hardware_crypto::delete_private_key(alias);
    result(std::nullopt);
}

void HardwareCryptoPlugin::Sign(
    const std::string& alias,
    const std::vector<uint8_t>& data,
    std::function<void(ErrorOr<std::vector<uint8_t>> reply)> result) {
    const auto private_key = hardware_crypto::load_private_key(alias);
    const auto signature = hardware_crypto::sign_message(private_key, data);
    result(signature);
}

}  // namespace hardware_crypto
