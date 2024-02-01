#include "include/hardware_crypto/hardware_crypto_plugin_c_api.h"

#include <flutter/plugin_registrar_windows.h>

#include "hardware_crypto_plugin.h"

void HardwareCryptoPluginCApiRegisterWithRegistrar(
    FlutterDesktopPluginRegistrarRef registrar) {
  hardware_crypto::HardwareCryptoPlugin::RegisterWithRegistrar(
      flutter::PluginRegistrarManager::GetInstance()
          ->GetRegistrar<flutter::PluginRegistrarWindows>(registrar));
}
