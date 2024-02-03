#include <cstdint>
#include <string>
#include <vector>

#include <cryptopp/eccrypto.h>

namespace hardware_crypto {

    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey generate_private_key();

    void save_private_key(
        const CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey& private_key,
        const std::string& name);

    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey load_private_key(const std::string& name);

    std::vector<uint8_t> sign_message(
        const CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey& private_key,
        const std::vector<uint8_t>& message);

    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey import_private_key(const std::string& contents);

    std::vector<uint8_t> export_public_key(const CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey& public_key);

    bool delete_private_key(const std::string& name);

}
