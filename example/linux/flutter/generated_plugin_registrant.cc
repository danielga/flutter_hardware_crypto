//
//  Generated file. Do not edit.
//

// clang-format off

#include "generated_plugin_registrant.h"

#include <hardware_crypto/hardware_crypto_plugin.h>

void fl_register_plugins(FlPluginRegistry* registry) {
  g_autoptr(FlPluginRegistrar) hardware_crypto_registrar =
      fl_plugin_registry_get_registrar_for_plugin(registry, "HardwareCryptoPlugin");
  hardware_crypto_plugin_register_with_registrar(hardware_crypto_registrar);
}
