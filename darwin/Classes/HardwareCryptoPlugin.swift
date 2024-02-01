#if os(iOS)
import Flutter
import UIKit

func messenger(from registrar: FlutterPluginRegistrar) -> FlutterBinaryMessenger {
    registrar.messenger()
}
#elseif os(macOS)
import Cocoa
import FlutterMacOS

func messenger(from registrar: FlutterPluginRegistrar) -> FlutterBinaryMessenger {
    registrar.messenger
}
#else
    #error("Unsupported platform.")
#endif

private enum HardwareCryptoError: Error {
    case failedToCopyPublicKey
    case failedToCopyExternalRepresentation
    case failedToCreateSignature
    case failedToImportKey
    case failedToCreateKey
}

public class HardwareCryptoPlugin: NSObject, FlutterPlugin {
    public static func register(with registrar: FlutterPluginRegistrar) {
        let api = HardwareCryptoImplementation()
        HardwareCryptoApiSetup.setUp(binaryMessenger: messenger(from: registrar), api: api)
    }
}

private class HardwareCryptoImplementation: HardwareCryptoApi {

    private static let keychainCommonParameters = [
        kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits: 256,
        kSecUseDataProtectionKeychain: true,
    ] as [String: Any]

    #if targetEnvironment(simulator)
    private static let keychainProtection = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    private static let keychainCreationAccessControlFlags: SecAccessControlCreateFlags = [.privateKeyUsage]
    private static let keychainImportAccessControlFlags: SecAccessControlCreateFlags = []
    #else
    private static let keychainProtection = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    private static let keychainCreationAccessControlFlags: SecAccessControlCreateFlags = [
        .privateKeyUsage, .biometryAny
    ]
    private static let keychainImportAccessControlFlags: SecAccessControlCreateFlags = [
        .biometryAny
    ]
    #endif

    private static let keychainCreationParameters = [
        kSecAttrTokenID: kSecAttrTokenIDSecureEnclave,
        kSecPrivateKeyAttrs: [
            kSecAttrAccessControl: SecAccessControlCreateWithFlags(
                nil,
                keychainProtection,
                keychainCreationAccessControlFlags,
                nil
            )!,
            kSecAttrIsPermanent: true,
        ] as [String: Any],
    ].merging(keychainCommonParameters) { (current, _) in current }

    private static let keychainImportParameters = [
        kSecAttrKeyClass: kSecAttrKeyClassPrivate,
        kSecAttrAccessControl: SecAccessControlCreateWithFlags(
            nil,
            keychainProtection,
            keychainImportAccessControlFlags,
            nil
        )!,
        kSecAttrIsPermanent: true,
    ].merging(keychainCommonParameters) { (current, _) in current }

    private static let keychainQueryParameters = [
        kSecClass: kSecClassKey,
        kSecReturnRef: true,
    ].merging(keychainCommonParameters) { (current, _) in current }

    private func getPrivateKey(alias: String) -> Result<SecKey, Error> {
        var parameters = Self.keychainQueryParameters
        parameters[kSecAttrApplicationLabel] = alias

        var queryResult: CFTypeRef?
        let status = SecItemCopyMatching(parameters as CFDictionary, &queryResult)
        guard status == errSecSuccess, let queryResult, CFGetTypeID(queryResult) == SecKeyGetTypeID() else {
            return .failure(NSError(domain: NSOSStatusErrorDomain, code: Int(status)))
        }

        return .success(queryResult as! SecKey)
    }

    func isSupported() throws -> Bool {
        return true
    }

    func importPEMKey(alias: String, key: String, completion: @escaping (Result<Void, Error>) -> Void) {
        let keyData: Data
        do {
            keyData = try SwKeyConvert.PrivateKey.pemToPKCS1DER(key)
        } catch {
            completion(.failure(error))
            return
        }

        var parameters = Self.keychainImportParameters
        parameters[kSecAttrApplicationLabel] = alias

        var error: Unmanaged<CFError>?
        let importedKey = SecKeyCreateWithData(keyData as CFData, parameters as CFDictionary, &error)
        if let importedKey {
            parameters[kSecValueRef] = importedKey
            let status = SecItemAdd(parameters as CFDictionary, nil)
            if (status != errSecSuccess) {
                completion(.failure(NSError(domain: NSOSStatusErrorDomain, code: Int(status))))
                return
            }

            completion(.success(()))
            return
        }

        guard let error else {
            completion(.failure(HardwareCryptoError.failedToImportKey))
            return
        }

        completion(.failure(error.takeRetainedValue()))
    }

    func generateKeyPair(alias: String, completion: @escaping (Result<Void, Error>) -> Void) {
        var parameters = Self.keychainCreationParameters
        parameters[kSecAttrApplicationLabel] = alias

        var error: Unmanaged<CFError>?
        let key = SecKeyCreateRandomKey(parameters as CFDictionary, &error)
        if key != nil {
            completion(.success(()))
            return
        }

        guard let error else {
            completion(.failure(HardwareCryptoError.failedToCreateKey))
            return
        }

        let errorValue = error.takeRetainedValue()
        // Consider duplicate key (ie. it has already been configured) a success case.
        if OSStatus(CFErrorGetCode(errorValue)) == errSecDuplicateItem {
            completion(.success(()))
            return
        }

        completion(.failure(errorValue))
    }

    func exportPublicKey(alias: String, completion: @escaping (Result<FlutterStandardTypedData, Error>) -> Void) {
        let result = getPrivateKey(alias: alias)
        let privateKey: SecKey
        switch result {
        case let .failure(error):
            completion(.failure(error))
            return

        case let .success(privKey):
            privateKey = privKey
        }

        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            completion(.failure(HardwareCryptoError.failedToCopyPublicKey))
            return
        }

        var error: Unmanaged<CFError>?
        let data = SecKeyCopyExternalRepresentation(publicKey, &error)
        if let data {
            completion(.success(.init(bytes: data as Data)))
            return
        }

        guard let error else {
            completion(.failure(HardwareCryptoError.failedToCopyExternalRepresentation))
            return
        }

        completion(.failure(error.takeRetainedValue()))
    }

    func deleteKeyPair(alias: String, completion: @escaping (Result<Void, Error>) -> Void) {
        var parameters = Self.keychainQueryParameters
        parameters[kSecAttrApplicationLabel] = alias
        let status = SecItemDelete(parameters as CFDictionary)
        if status == errSecSuccess {
            completion(.success(()))
            return
        }

        completion(.failure(NSError(domain: NSOSStatusErrorDomain, code: Int(status))))
    }

    func sign(alias: String, data: FlutterStandardTypedData, completion: @escaping (Result<FlutterStandardTypedData, Error>) -> Void) {
        let result = getPrivateKey(alias: alias)
        let privateKey: SecKey
        switch result {
        case let .failure(error):
            completion(.failure(error))
            return

        case let .success(privKey):
            privateKey = privKey
        }

        var error: Unmanaged<CFError>?
        let signature = SecKeyCreateSignature(
            privateKey,
            .ecdsaSignatureMessageX962SHA256,
            data.data as CFData,
            &error
        )
        if let signature {
            completion(.success(.init(bytes: signature as Data)))
            return
        }

        guard let error else {
            completion(.failure(HardwareCryptoError.failedToCreateSignature))
            return
        }

        completion(.failure(error.takeRetainedValue()))
    }

}
