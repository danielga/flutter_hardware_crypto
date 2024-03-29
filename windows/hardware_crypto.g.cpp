// Autogenerated from Pigeon (v16.0.5), do not edit directly.
// See also: https://pub.dev/packages/pigeon

#undef _HAS_EXCEPTIONS

#include "hardware_crypto.g.hpp"

#include <flutter/basic_message_channel.h>
#include <flutter/binary_messenger.h>
#include <flutter/encodable_value.h>
#include <flutter/standard_message_codec.h>

#include <map>
#include <optional>
#include <string>

namespace hardware_crypto {
using flutter::BasicMessageChannel;
using flutter::CustomEncodableValue;
using flutter::EncodableList;
using flutter::EncodableMap;
using flutter::EncodableValue;

FlutterError CreateConnectionError(const std::string channel_name) {
    return FlutterError(
        "channel-error",
        "Unable to establish connection on channel: '" + channel_name + "'.",
        EncodableValue(""));
}

/// The codec used by HardwareCryptoApi.
const flutter::StandardMessageCodec& HardwareCryptoApi::GetCodec() {
  return flutter::StandardMessageCodec::GetInstance(&flutter::StandardCodecSerializer::GetInstance());
}

// Sets up an instance of `HardwareCryptoApi` to handle messages through the `binary_messenger`.
void HardwareCryptoApi::SetUp(
  flutter::BinaryMessenger* binary_messenger,
  HardwareCryptoApi* api) {
  {
    auto channel = std::make_unique<BasicMessageChannel<>>(binary_messenger, "dev.flutter.pigeon.hardware_crypto.HardwareCryptoApi.isSupported", &GetCodec());
    if (api != nullptr) {
      channel->SetMessageHandler([api](const EncodableValue& message, const flutter::MessageReply<EncodableValue>& reply) {
        try {
          ErrorOr<bool> output = api->IsSupported();
          if (output.has_error()) {
            reply(WrapError(output.error()));
            return;
          }
          EncodableList wrapped;
          wrapped.push_back(EncodableValue(std::move(output).TakeValue()));
          reply(EncodableValue(std::move(wrapped)));
        } catch (const std::exception& exception) {
          reply(WrapError(exception.what()));
        }
      });
    } else {
      channel->SetMessageHandler(nullptr);
    }
  }
  {
    auto channel = std::make_unique<BasicMessageChannel<>>(binary_messenger, "dev.flutter.pigeon.hardware_crypto.HardwareCryptoApi.importPEMKey", &GetCodec());
    if (api != nullptr) {
      channel->SetMessageHandler([api](const EncodableValue& message, const flutter::MessageReply<EncodableValue>& reply) {
        try {
          const auto& args = std::get<EncodableList>(message);
          const auto& encodable_alias_arg = args.at(0);
          if (encodable_alias_arg.IsNull()) {
            reply(WrapError("alias_arg unexpectedly null."));
            return;
          }
          const auto& alias_arg = std::get<std::string>(encodable_alias_arg);
          const auto& encodable_key_arg = args.at(1);
          if (encodable_key_arg.IsNull()) {
            reply(WrapError("key_arg unexpectedly null."));
            return;
          }
          const auto& key_arg = std::get<std::string>(encodable_key_arg);
          api->ImportPEMKey(alias_arg, key_arg, [reply](std::optional<FlutterError>&& output) {
            if (output.has_value()) {
              reply(WrapError(output.value()));
              return;
            }
            EncodableList wrapped;
            wrapped.push_back(EncodableValue());
            reply(EncodableValue(std::move(wrapped)));
          });
        } catch (const std::exception& exception) {
          reply(WrapError(exception.what()));
        }
      });
    } else {
      channel->SetMessageHandler(nullptr);
    }
  }
  {
    auto channel = std::make_unique<BasicMessageChannel<>>(binary_messenger, "dev.flutter.pigeon.hardware_crypto.HardwareCryptoApi.generateKeyPair", &GetCodec());
    if (api != nullptr) {
      channel->SetMessageHandler([api](const EncodableValue& message, const flutter::MessageReply<EncodableValue>& reply) {
        try {
          const auto& args = std::get<EncodableList>(message);
          const auto& encodable_alias_arg = args.at(0);
          if (encodable_alias_arg.IsNull()) {
            reply(WrapError("alias_arg unexpectedly null."));
            return;
          }
          const auto& alias_arg = std::get<std::string>(encodable_alias_arg);
          api->GenerateKeyPair(alias_arg, [reply](std::optional<FlutterError>&& output) {
            if (output.has_value()) {
              reply(WrapError(output.value()));
              return;
            }
            EncodableList wrapped;
            wrapped.push_back(EncodableValue());
            reply(EncodableValue(std::move(wrapped)));
          });
        } catch (const std::exception& exception) {
          reply(WrapError(exception.what()));
        }
      });
    } else {
      channel->SetMessageHandler(nullptr);
    }
  }
  {
    auto channel = std::make_unique<BasicMessageChannel<>>(binary_messenger, "dev.flutter.pigeon.hardware_crypto.HardwareCryptoApi.exportPublicKey", &GetCodec());
    if (api != nullptr) {
      channel->SetMessageHandler([api](const EncodableValue& message, const flutter::MessageReply<EncodableValue>& reply) {
        try {
          const auto& args = std::get<EncodableList>(message);
          const auto& encodable_alias_arg = args.at(0);
          if (encodable_alias_arg.IsNull()) {
            reply(WrapError("alias_arg unexpectedly null."));
            return;
          }
          const auto& alias_arg = std::get<std::string>(encodable_alias_arg);
          api->ExportPublicKey(alias_arg, [reply](ErrorOr<std::vector<uint8_t>>&& output) {
            if (output.has_error()) {
              reply(WrapError(output.error()));
              return;
            }
            EncodableList wrapped;
            wrapped.push_back(EncodableValue(std::move(output).TakeValue()));
            reply(EncodableValue(std::move(wrapped)));
          });
        } catch (const std::exception& exception) {
          reply(WrapError(exception.what()));
        }
      });
    } else {
      channel->SetMessageHandler(nullptr);
    }
  }
  {
    auto channel = std::make_unique<BasicMessageChannel<>>(binary_messenger, "dev.flutter.pigeon.hardware_crypto.HardwareCryptoApi.deleteKeyPair", &GetCodec());
    if (api != nullptr) {
      channel->SetMessageHandler([api](const EncodableValue& message, const flutter::MessageReply<EncodableValue>& reply) {
        try {
          const auto& args = std::get<EncodableList>(message);
          const auto& encodable_alias_arg = args.at(0);
          if (encodable_alias_arg.IsNull()) {
            reply(WrapError("alias_arg unexpectedly null."));
            return;
          }
          const auto& alias_arg = std::get<std::string>(encodable_alias_arg);
          api->DeleteKeyPair(alias_arg, [reply](std::optional<FlutterError>&& output) {
            if (output.has_value()) {
              reply(WrapError(output.value()));
              return;
            }
            EncodableList wrapped;
            wrapped.push_back(EncodableValue());
            reply(EncodableValue(std::move(wrapped)));
          });
        } catch (const std::exception& exception) {
          reply(WrapError(exception.what()));
        }
      });
    } else {
      channel->SetMessageHandler(nullptr);
    }
  }
  {
    auto channel = std::make_unique<BasicMessageChannel<>>(binary_messenger, "dev.flutter.pigeon.hardware_crypto.HardwareCryptoApi.sign", &GetCodec());
    if (api != nullptr) {
      channel->SetMessageHandler([api](const EncodableValue& message, const flutter::MessageReply<EncodableValue>& reply) {
        try {
          const auto& args = std::get<EncodableList>(message);
          const auto& encodable_alias_arg = args.at(0);
          if (encodable_alias_arg.IsNull()) {
            reply(WrapError("alias_arg unexpectedly null."));
            return;
          }
          const auto& alias_arg = std::get<std::string>(encodable_alias_arg);
          const auto& encodable_data_arg = args.at(1);
          if (encodable_data_arg.IsNull()) {
            reply(WrapError("data_arg unexpectedly null."));
            return;
          }
          const auto& data_arg = std::get<std::vector<uint8_t>>(encodable_data_arg);
          api->Sign(alias_arg, data_arg, [reply](ErrorOr<std::vector<uint8_t>>&& output) {
            if (output.has_error()) {
              reply(WrapError(output.error()));
              return;
            }
            EncodableList wrapped;
            wrapped.push_back(EncodableValue(std::move(output).TakeValue()));
            reply(EncodableValue(std::move(wrapped)));
          });
        } catch (const std::exception& exception) {
          reply(WrapError(exception.what()));
        }
      });
    } else {
      channel->SetMessageHandler(nullptr);
    }
  }
}

EncodableValue HardwareCryptoApi::WrapError(std::string_view error_message) {
  return EncodableValue(EncodableList{
    EncodableValue(std::string(error_message)),
    EncodableValue("Error"),
    EncodableValue()
  });
}

EncodableValue HardwareCryptoApi::WrapError(const FlutterError& error) {
  return EncodableValue(EncodableList{
    EncodableValue(error.code()),
    EncodableValue(error.message()),
    error.details()
  });
}

}  // namespace hardware_crypto
