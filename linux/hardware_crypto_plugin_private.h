#include <flutter_linux/flutter_linux.h>

#include "include/hardware_crypto/hardware_crypto_plugin.h"

// This file exposes some plugin internals for unit testing. See
// https://github.com/flutter/flutter/issues/88724 for current limitations
// in the unit-testable API.

FlValue *hardware_crypto_plugin_isSupported();
FlValue *hardware_crypto_plugin_generateKeyPair(FlValue *message);
FlValue *hardware_crypto_plugin_deleteKeyPair(FlValue *message);
FlValue *hardware_crypto_plugin_sign(FlValue *message);
