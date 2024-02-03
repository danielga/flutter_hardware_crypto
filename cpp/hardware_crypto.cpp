#include "hardware_crypto.hpp"

#if defined( _WIN32 )
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shlobj.h>
#elif defined( __linux__  )
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#else
#error "Unsupported platform!"
#endif

#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <sstream>
#include <string>
#include <vector>

#include <cryptopp/base64.h>
#include <cryptopp/dsa.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/files.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/osrng.h>
#include <cryptopp/oids.h>

namespace hardware_crypto
{

#if defined( _WIN32 )
    static std::string utf8_encode(const wchar_t* wstr)
    {
        const size_t wstr_len = std::wcslen(wstr);
        if (wstr_len == 0 || wstr_len >= INT32_MAX)
        {
            return std::string();
        }

        const int len = static_cast<int>(wstr_len);
        const int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr, len, nullptr, 0, nullptr, nullptr);
        if (size_needed == 0)
        {
            return std::string();
        }

        std::string str(size_needed, 0);
        const int result = WideCharToMultiByte(CP_UTF8, 0, wstr, len, str.data(), size_needed, nullptr, nullptr);
        if (result == 0)
        {
            return std::string();
        }

        return str;
    }
#endif

    static std::filesystem::path data_directory()
    {
#if defined( _WIN32 )
        wchar_t* temp_path = nullptr;
        const auto result = SHGetKnownFolderPath(FOLDERID_LocalAppData, KF_FLAG_DEFAULT, nullptr, &temp_path);
        if (result != S_OK)
        {
            CoTaskMemFree(temp_path);
            throw std::runtime_error("unable to get current user's home directory");
        }

        const auto path = utf8_encode(temp_path);
        CoTaskMemFree(temp_path);

        if (path.empty())
        {
            throw std::runtime_error("unable to get current user's home directory");
        }

        return std::filesystem::path(path);
#elif defined( __linux__  )
        const auto pw = getpwuid(getuid());
        if (pw == nullptr)
        {
            throw std::runtime_error("unable to get current user's home directory");
        }

        return std::filesystem::path(pw->pw_dir) / ".local/share/hardware_crypto";
#else
#error "Unsupported platform!"
#endif
    }

    static std::filesystem::path data_path(const std::string& path)
    {
        const auto data_dir = data_directory();
        return data_dir / path;
    }

    static std::string cleanup_pem_key(const std::string& key)
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

    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey generate_private_key()
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

    void save_private_key(
        const CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey& private_key,
        const std::string& name)
    {
        const auto path = data_path(name);
        std::filesystem::create_directories(path);
        CryptoPP::FileSink file(path.c_str());
        private_key.Save(file);
    }

    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey load_private_key(const std::string& name)
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

    std::vector<uint8_t> sign_message(
        const CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey& private_key,
        const std::vector<uint8_t>& message)
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

    CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey import_private_key(const std::string& contents)
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

    std::vector<uint8_t> export_public_key(const CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey& public_key)
    {
        std::vector<uint8_t> data;
        CryptoPP::VectorSink s(data);
        public_key.Save(s);
        return std::vector<uint8_t>(data.end() - 65, data.end());
    }

    bool delete_private_key(const std::string& name)
    {
        return std::filesystem::remove(data_path(name));
    }

}
