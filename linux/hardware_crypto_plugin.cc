#include "include/hardware_crypto/hardware_crypto_plugin.h"

#include <flutter_linux/flutter_linux.h>
#include <gtk/gtk.h>
#include <sys/utsname.h>

#include "hardware_crypto_plugin_private.h"

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

static std::filesystem::path data_directory()
{
  const auto pw = getpwuid(getuid());
  if (pw == nullptr)
  {
    throw std::runtime_error("unable to get current user's home directory");
  }

  return std::filesystem::path(pw->pw_dir) / ".local/share/hardware_crypto";
}

static std::filesystem::path data_path(const std::string &path)
{
  const auto data_dir = data_directory();
  std::filesystem::create_directories(data_dir);
  return data_dir / path;
}

static CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey generate_private_key()
{
  CryptoPP::AutoSeededRandomPool prng;
  CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey private_key;
  private_key.Initialize(prng, CryptoPP::ASN1::secp256r1());
  bool result = private_key.Validate(prng, 3);
  if (!result)
  {
    throw std::runtime_error("unable to generate secp256r1 private key");
  }

  return private_key;
}

static void save_private_key(
    const CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey &private_key,
    const std::string &name)
{
  CryptoPP::FileSink file(data_path(name).c_str());
  private_key.Save(file);
}

static CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey load_private_key(const std::string &name)
{
  CryptoPP::FileSource file(data_path(name).c_str(), true);
  CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey private_key;
  private_key.Load(file);

  CryptoPP::AutoSeededRandomPool prng;
  bool result = private_key.Validate(prng, 3);
  if (!result)
  {
    throw std::runtime_error("unable to load secp256r1 private key");
  }

  return private_key;
}

static std::vector<uint8_t> sign_message(
    const CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey &private_key,
    const std::vector<uint8_t> &message)
{
  CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Signer signer(private_key);
  std::vector<uint8_t> p1363_signature;
  CryptoPP::AutoSeededRandomPool prng;
  CryptoPP::VectorSource s(
      message,
      true,
      new CryptoPP::SignerFilter(
          prng,
          signer,
          new CryptoPP::VectorSink(p1363_signature)));

  std::vector<uint8_t> der_signature;
  der_signature.resize(3 + 3 + 3 + 2 + p1363_signature.size());

  const size_t encoded_size = CryptoPP::DSAConvertSignatureFormat(
      der_signature.data(), der_signature.size(), CryptoPP::DSA_DER,
      p1363_signature.data(), p1363_signature.size(), CryptoPP::DSA_P1363);
  der_signature.resize(encoded_size);
  return der_signature;
}

static bool verify_signature(
    const CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey &public_key,
    const std::string &message,
    const std::vector<uint8_t> &der_signature)
{
  try
  {
    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Verifier verifier(public_key);

    std::vector<uint8_t> p1363_signature;
    p1363_signature.resize(verifier.SignatureLength());

    CryptoPP::DSAConvertSignatureFormat(
        p1363_signature.data(), p1363_signature.size(), CryptoPP::DSA_P1363,
        der_signature.data(), der_signature.size(), CryptoPP::DSA_DER);

    p1363_signature.insert(p1363_signature.end(), message.begin(), message.end());

    CryptoPP::VectorSource ss(
        p1363_signature,
        true,
        new CryptoPP::SignatureVerificationFilter(
            CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Verifier(public_key),
            nullptr,
            CryptoPP::SignatureVerificationFilter::SIGNATURE_AT_BEGIN | CryptoPP::SignatureVerificationFilter::THROW_EXCEPTION));
    return true;
  }
  catch (const std::exception &)
  {
    return false;
  }
}

static std::string hex_encode(const std::vector<uint8_t> &data)
{
  std::string encoded;

  CryptoPP::StringSource ss(
      data.data(),
      data.size(),
      true,
      new CryptoPP::HexEncoder(
          new CryptoPP::StringSink(encoded)));

  return encoded;
}

static std::string cleanup_pem_key(const std::string &key)
{
  static const std::string privateKeyPrefix = "-----BEGIN PRIVATE KEY-----\n";
  static const std::string privateKeySuffix = "\n-----END PRIVATE KEY-----";

  size_t start = key.find(privateKeyPrefix), end = key.find(privateKeySuffix);
  if (start == key.npos)
  {
    start = 0;
  }
  else
  {
    start += privateKeyPrefix.size();
  }

  if (end == key.npos)
  {
    end = key.size() - start;
  }
  else
  {
    end -= start;
  }

  return key.substr(start, end);
}

static CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey import_private_key(const std::string &contents)
{
  const auto clean_key = cleanup_pem_key(contents);

  CryptoPP::StringSource source(clean_key, true, new CryptoPP::Base64Decoder(nullptr));
  CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey private_key;
  private_key.Load(source);

  CryptoPP::AutoSeededRandomPool prng;
  bool result = private_key.Validate(prng, 3);
  if (!result)
  {
    throw std::runtime_error("unable to load secp256r1 private key");
  }

  return private_key;
}

static std::vector<uint8_t> export_public_key(const CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey &public_key)
{
  std::vector<uint8_t> data;
  CryptoPP::VectorSink s(data);
  public_key.Save(s);
  return std::vector<uint8_t>(data.end() - 65, data.end());
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
  const gchar *name = fl_value_get_string(fl_value_get_list_value(message, 0));
  const gchar *contents = fl_value_get_string(fl_value_get_list_value(message, 1));
  const auto private_key = import_private_key(contents);
  save_private_key(private_key, name);
  return fl_value_new_null();
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
  const auto name = fl_value_get_string(fl_value_get_list_value(message, 0));
  const auto private_key = generate_private_key();
  save_private_key(private_key, name);
  return fl_value_new_null();
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
  const auto name = fl_value_get_string(fl_value_get_list_value(message, 0));
  const auto private_key = load_private_key(name);
  CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey public_key;
  private_key.MakePublicKey(public_key);
  const auto public_key_data = export_public_key(public_key);
  return fl_value_new_uint8_list(public_key_data.data(), public_key_data.size());
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
  const auto name = fl_value_get_string(fl_value_get_list_value(message, 0));
  std::filesystem::remove(data_path(name));
  return fl_value_new_null();
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
  const gchar *name = fl_value_get_string(fl_value_get_list_value(message, 0));
  auto arg1 = fl_value_get_list_value(message, 1);
  const uint8_t *data = fl_value_get_uint8_list(arg1);
  const size_t data_len = fl_value_get_length(arg1);
  const auto private_key = load_private_key(name);
  const auto signature = sign_message(private_key, std::vector<uint8_t>(data, data + data_len));
  return fl_value_new_uint8_list(signature.data(), signature.size());
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
