#include <flutter_linux/flutter_linux.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "include/hardware_crypto/hardware_crypto_plugin.h"
#include "hardware_crypto_plugin_private.h"

// This demonstrates a simple unit test of the C portion of this plugin's
// implementation.
//
// Once you have built the plugin's example app, you can run these tests
// from the command line. For instance, for a plugin called my_plugin
// built for x64 debug, run:
// $ build/linux/x64/debug/plugins/my_plugin/my_plugin_test

namespace hardware_crypto {
namespace test {

TEST(HardwareCryptoPlugin, IsSupported) {
  g_autoptr(FlValue) result = hardware_crypto_plugin_isSupported();
  ASSERT_NE(result, nullptr);
  ASSERT_EQ(fl_value_get_type(result), FL_VALUE_TYPE_BOOL);
  EXPECT_THAT(fl_value_get_bool(result), false);
}

}  // namespace test
}  // namespace hardware_crypto
