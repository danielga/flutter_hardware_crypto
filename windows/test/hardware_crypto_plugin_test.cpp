#include <flutter/method_call.h>
#include <flutter/method_result_functions.h>
#include <flutter/standard_method_codec.h>
#include <gtest/gtest.h>
#include <windows.h>

#include <memory>
#include <string>
#include <variant>

#include "hardware_crypto_plugin.hpp"

namespace hardware_crypto {
namespace test {

namespace {

using flutter::EncodableMap;
using flutter::EncodableValue;
using flutter::MethodCall;
using flutter::MethodResultFunctions;

}  // namespace

TEST(HardwareCryptoPlugin, IsSupported) {
  HardwareCryptoPlugin plugin;
  EXPECT_TRUE(plugin.IsSupported().value());
}

}  // namespace test
}  // namespace hardware_crypto
