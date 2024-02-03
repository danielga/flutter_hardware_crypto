#include "hardware_crypto_plugin_private.h"

#include <hardware_crypto.h>

#include <flutter_linux/flutter_linux.h>
#include <gtk/gtk.h>
#include <sys/utsname.h>

#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <sstream>
#include <string>
#include <vector>

#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>

#include <cryptopp/base64.h>
#include <cryptopp/dsa.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/files.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/osrng.h>
#include <cryptopp/oids.h>

#define HARDWARE_CRYPTO_PLUGIN(obj)                                     \
  (G_TYPE_CHECK_INSTANCE_CAST((obj), hardware_crypto_plugin_get_type(), \
                              HardwareCryptoPlugin))

struct _HardwareCryptoPlugin
{
  GObject parent_instance;
};

G_DEFINE_TYPE(HardwareCryptoPlugin, hardware_crypto_plugin, g_object_get_type())

static void hardware_crypto_plugin_dispose(GObject *object)
{
  G_OBJECT_CLASS(hardware_crypto_plugin_parent_class)->dispose(object);
}

static void hardware_crypto_plugin_class_init(HardwareCryptoPluginClass *klass)
{
  G_OBJECT_CLASS(klass)->dispose = hardware_crypto_plugin_dispose;
}

static void hardware_crypto_plugin_init(HardwareCryptoPlugin *self) {}

FlValue *hardware_crypto_plugin_send_exception(const std::exception& exception)
{
  const auto err = fl_value_new_list();
  fl_value_append_take(self->value, fl_value_new_string(exception.what()));
  fl_value_append_take(self->value, fl_value_new_string("Error"));
  fl_value_append_take(self->value, fl_value_new_null());
  return err;
}

FlValue *hardware_crypto_plugin_isSupported()
{
  return fl_value_new_bool(true);
}

static void hardware_crypto_plugin_handle_isSupported(
    FlBasicMessageChannel *channel,
    FlValue *message,
    FlBasicMessageChannelResponseHandle *response_handle,
    gpointer user_data)
{
  FlValue *response = hardware_crypto_plugin_isSupported();
  g_autoptr(FlValue) value = fl_value_new_list();
  fl_value_append_take(value, response);
  fl_basic_message_channel_respond(channel, response_handle, value, NULL);
}

FlValue *hardware_crypto_plugin_importPEMKey(FlValue *message)
{
  try {
    const gchar *name = fl_value_get_string(fl_value_get_list_value(message, 0));
    const gchar *contents = fl_value_get_string(fl_value_get_list_value(message, 1));
    const auto private_key = hardware_crypto::import_private_key(contents);
    hardware_crypto::save_private_key(private_key, name);
    return fl_value_new_null();
  } catch (const std::exception &e) {
    return hardware_crypto_plugin_send_exception(e);
  }
}

static void hardware_crypto_plugin_handle_importPEMKey(
    FlBasicMessageChannel *channel,
    FlValue *message,
    FlBasicMessageChannelResponseHandle *response_handle,
    gpointer user_data)
{
  FlValue *response = hardware_crypto_plugin_importPEMKey(message);
  g_autoptr(FlValue) value = fl_value_new_list();
  fl_value_append_take(value, response);
  fl_basic_message_channel_respond(channel, response_handle, value, NULL);
}

FlValue *hardware_crypto_plugin_generateKeyPair(FlValue *message)
{
  try {
    const auto name = fl_value_get_string(fl_value_get_list_value(message, 0));
    const auto private_key = hardware_crypto::generate_private_key();
    hardware_crypto::save_private_key(private_key, name);
    return fl_value_new_null();
  } catch (const std::exception &e) {
    return hardware_crypto_plugin_send_exception(e);
  }
}

static void hardware_crypto_plugin_handle_generateKeyPair(
    FlBasicMessageChannel *channel,
    FlValue *message,
    FlBasicMessageChannelResponseHandle *response_handle,
    gpointer user_data)
{
  FlValue *response = hardware_crypto_plugin_generateKeyPair(message);
  g_autoptr(FlValue) value = fl_value_new_list();
  fl_value_append_take(value, response);
  fl_basic_message_channel_respond(channel, response_handle, value, NULL);
}

FlValue *hardware_crypto_plugin_exportPublicKey(FlValue *message)
{
  try {
    const auto name = fl_value_get_string(fl_value_get_list_value(message, 0));
    const auto private_key = hardware_crypto::load_private_key(name);
    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey public_key;
    private_key.MakePublicKey(public_key);
    const auto public_key_data = hardware_crypto::export_public_key(public_key);
    return fl_value_new_uint8_list(public_key_data.data(), public_key_data.size());
  } catch (const std::exception &e) {
    return hardware_crypto_plugin_send_exception(e);
  }
}

static void hardware_crypto_plugin_handle_exportPublicKey(
    FlBasicMessageChannel *channel,
    FlValue *message,
    FlBasicMessageChannelResponseHandle *response_handle,
    gpointer user_data)
{
  FlValue *response = hardware_crypto_plugin_exportPublicKey(message);
  g_autoptr(FlValue) value = fl_value_new_list();
  fl_value_append_take(value, response);
  fl_basic_message_channel_respond(channel, response_handle, value, NULL);
}

FlValue *hardware_crypto_plugin_deleteKeyPair(FlValue *message)
{
  try {
    const auto name = fl_value_get_string(fl_value_get_list_value(message, 0));
    hardware_crypto::delete_private_key(name);
    return fl_value_new_null();
  } catch (const std::exception &e) {
    return hardware_crypto_plugin_send_exception(e);
  }
}

static void hardware_crypto_plugin_handle_deleteKeyPair(
    FlBasicMessageChannel *channel,
    FlValue *message,
    FlBasicMessageChannelResponseHandle *response_handle,
    gpointer user_data)
{
  FlValue *response = hardware_crypto_plugin_deleteKeyPair(message);
  g_autoptr(FlValue) value = fl_value_new_list();
  fl_value_append_take(value, response);
  fl_basic_message_channel_respond(channel, response_handle, value, NULL);
}

FlValue *hardware_crypto_plugin_sign(FlValue *message)
{
  try {
    const gchar *name = fl_value_get_string(fl_value_get_list_value(message, 0));
    auto arg1 = fl_value_get_list_value(message, 1);
    const uint8_t *data = fl_value_get_uint8_list(arg1);
    const size_t data_len = fl_value_get_length(arg1);
    const auto private_key = hardware_crypto::load_private_key(name);
    const auto signature = hardware_crypto::sign_message(private_key, std::vector<uint8_t>(data, data + data_len));
    return fl_value_new_uint8_list(signature.data(), signature.size());
  } catch (const std::exception &e) {
    return hardware_crypto_plugin_send_exception(e);
  }
}

static void hardware_crypto_plugin_handle_sign(
    FlBasicMessageChannel *channel,
    FlValue *message,
    FlBasicMessageChannelResponseHandle *response_handle,
    gpointer user_data)
{
  FlValue *response = hardware_crypto_plugin_sign(message);
  g_autoptr(FlValue) value = fl_value_new_list();
  fl_value_append_take(value, response);
  fl_basic_message_channel_respond(channel, response_handle, value, NULL);
}

void hardware_crypto_plugin_register_with_registrar(FlPluginRegistrar *registrar)
{
  HardwareCryptoPlugin *plugin = HARDWARE_CRYPTO_PLUGIN(
      g_object_new(hardware_crypto_plugin_get_type(), nullptr));

  g_autoptr(FlStandardMessageCodec) codec = fl_standard_message_codec_new();

  g_autoptr(FlBasicMessageChannel) isSupportedChannel = fl_basic_message_channel_new(
      fl_plugin_registrar_get_messenger(registrar),
      "dev.flutter.pigeon.hardware_crypto.HardwareCryptoApi.isSupported",
      FL_MESSAGE_CODEC(codec));
  fl_basic_message_channel_set_message_handler(
      isSupportedChannel,
      hardware_crypto_plugin_handle_isSupported,
      g_object_ref(plugin),
      g_object_unref);

  g_autoptr(FlBasicMessageChannel) importPEMKeyChannel = fl_basic_message_channel_new(
      fl_plugin_registrar_get_messenger(registrar),
      "dev.flutter.pigeon.hardware_crypto.HardwareCryptoApi.importPEMKey",
      FL_MESSAGE_CODEC(codec));
  fl_basic_message_channel_set_message_handler(
      importPEMKeyChannel,
      hardware_crypto_plugin_handle_importPEMKey,
      g_object_ref(plugin),
      g_object_unref);

  g_autoptr(FlBasicMessageChannel) generateKeyPairChannel = fl_basic_message_channel_new(
      fl_plugin_registrar_get_messenger(registrar),
      "dev.flutter.pigeon.hardware_crypto.HardwareCryptoApi.generateKeyPair",
      FL_MESSAGE_CODEC(codec));
  fl_basic_message_channel_set_message_handler(
      generateKeyPairChannel,
      hardware_crypto_plugin_handle_generateKeyPair,
      g_object_ref(plugin),
      g_object_unref);

  g_autoptr(FlBasicMessageChannel) exportPublicKeyChannel = fl_basic_message_channel_new(
      fl_plugin_registrar_get_messenger(registrar),
      "dev.flutter.pigeon.hardware_crypto.HardwareCryptoApi.exportPublicKey",
      FL_MESSAGE_CODEC(codec));
  fl_basic_message_channel_set_message_handler(
      exportPublicKeyChannel,
      hardware_crypto_plugin_handle_exportPublicKey,
      g_object_ref(plugin),
      g_object_unref);

  g_autoptr(FlBasicMessageChannel) deleteKeyPairChannel = fl_basic_message_channel_new(
      fl_plugin_registrar_get_messenger(registrar),
      "dev.flutter.pigeon.hardware_crypto.HardwareCryptoApi.deleteKeyPair",
      FL_MESSAGE_CODEC(codec));
  fl_basic_message_channel_set_message_handler(
      deleteKeyPairChannel,
      hardware_crypto_plugin_handle_deleteKeyPair,
      g_object_ref(plugin),
      g_object_unref);

  g_autoptr(FlBasicMessageChannel) signChannel = fl_basic_message_channel_new(
      fl_plugin_registrar_get_messenger(registrar),
      "dev.flutter.pigeon.hardware_crypto.HardwareCryptoApi.sign",
      FL_MESSAGE_CODEC(codec));
  fl_basic_message_channel_set_message_handler(
      signChannel,
      hardware_crypto_plugin_handle_sign,
      g_object_ref(plugin),
      g_object_unref);

  g_object_unref(plugin);
}
