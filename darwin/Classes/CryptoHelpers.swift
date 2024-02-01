/// MIT License
/// 
/// Copyright (c) 2016 Soyer
/// 
/// Permission is hereby granted, free of charge, to any person obtaining a
/// copy of this software and associated documentation files (the "Software"),
/// to deal in the Software without restriction, including without limitation
/// the rights to use, copy, modify, merge, publish, distribute, sublicense,
/// and/or sell copies of the Software, and to permit persons to whom the
/// Software is furnished to do so, subject to the following conditions:
/// 
/// The above copyright notice and this permission notice shall be included in
/// all copies or substantial portions of the Software.
/// 
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
/// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
/// DEALINGS IN THE SOFTWARE.

import Foundation

public enum SwError: Error {
    case invalidKey
    case badPassphrase
    case keyNotEncrypted
    case parse(String)
}

public struct SwKeyConvert {

    public struct PrivateKey {

        public static func pemToPKCS1DER(_ pemKey: String) throws -> Data {
            guard let derKey = try? PEM.PrivateKey.toDER(pemKey) else {
                throw SwError.invalidKey
            }
            guard let pkcs1DERKey = PKCS8.PrivateKey.stripHeaderIfAny(derKey) else {
                throw SwError.invalidKey
            }
            return pkcs1DERKey
        }

    }

}

private struct PKCS8 {

    struct PrivateKey {

        // https://lapo.it/asn1js/
        static func getPKCS1DEROffset(_ derKey: Data) -> Int? {
            var offset = 0
            guard derKey.count > offset else { return nil }
            guard derKey[offset] == 0x30 else { return nil }

            offset += 1

            guard derKey.count > offset else { return nil }
            if derKey[offset] > 0x80 {
                offset += Int(derKey[offset]) - 0x80
            }
            offset += 1

            guard derKey.count > offset else { return nil }
            guard derKey[offset] == 0x02 else { return nil }

            offset += 3

            // without PKCS8 header
            guard derKey.count > offset else { return nil }
            if derKey[offset] == 0x02 {
                return 0
            }

            let OID: [UInt8] = [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
                                0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00]

            guard derKey.count > offset + OID.count else { return nil }
            guard OID.elementsEqual(derKey[offset..<offset + OID.count]) else { return nil }

            offset += OID.count

            guard derKey.count > offset else { return nil }
            guard derKey[offset] == 0x04 else { return nil }

            offset += 1

            guard derKey.count > offset else { return nil }
            if derKey[offset] > 0x80 {
                offset += Int(derKey[offset]) - 0x80
            }
            offset += 1

            guard derKey.count > offset else { return nil }
            guard derKey[offset] == 0x30 else { return nil }

            return offset
        }

        // https://lapo.it/asn1js/
        static func extractANSIX692Key(_ derKey: Data) -> Data? {
            var offset = 0
            guard derKey.count > offset else { return nil }
            guard derKey[offset] == 0x30 else { return nil }

            offset += 1

            guard derKey.count > offset else { return nil }
            if derKey[offset] > 0x80 {
                offset += Int(derKey[offset]) - 0x80
            }

            offset += 1

            guard derKey.count > offset else { return nil }
            guard derKey[offset] == 0x02 else { return nil }

            offset += 3

            guard derKey.count > offset else { return nil }
            if derKey[offset] == 0x02 {
                return nil
            }

            let OID: [UInt8] = [
                0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce,
                0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48,
                0xce, 0x3d, 0x03, 0x01, 0x07
            ]

            guard derKey.count > offset + OID.count else { return nil }
            let slice = derKey[offset..<offset + OID.count]

            guard OID.elementsEqual(slice) else { return nil }

            offset += OID.count

            guard derKey.count > offset else { return nil }
            guard derKey[offset] == 0x04 else { return nil }

            offset += 2

            guard derKey.count > offset else { return nil }
            guard derKey[offset] == 0x30 else { return nil }

            offset += 2

            guard derKey.count > offset else { return nil }
            guard derKey[offset] == 0x02 else { return nil }

            offset += 3

            guard derKey.count > offset else { return nil }
            guard derKey[offset] == 0x04 else { return nil }

            offset += 2

            guard derKey.count >= offset + 32 else { return nil }

            let k = derKey[offset..<offset + 32]

            offset += 32

            guard derKey.count > offset else { return nil }
            guard derKey[offset] == 0xa1 else { return nil }

            offset += 2

            guard derKey.count > offset else { return nil }
            guard derKey[offset] == 0x03 else { return nil }

            offset += 2

            guard derKey.count >= offset + 66 else { return nil }

            offset += 1

            let ansix692Public = derKey[offset..<offset + 65]
            return ansix692Public + k
        }

        static func stripHeaderIfAny(_ derKey: Data) -> Data? {
            if let ecKey = extractANSIX692Key(derKey) {
                return ecKey
            }
            guard let offset = getPKCS1DEROffset(derKey) else {
                return nil
            }
            return derKey.subdata(in: offset..<derKey.count)
        }

    }

}

private struct PEM {

    struct PrivateKey {

        static func toDER(_ pemKey: String) throws -> Data {
            guard let strippedKey = stripHeader(pemKey) else {
                throw SwError.parse("header")
            }
            guard let data = PEM.base64Decode(strippedKey) else {
                throw SwError.parse("base64decode")
            }
            return data
        }

        static let prefix = "-----BEGIN PRIVATE KEY-----\n"
        static let suffix = "\n-----END PRIVATE KEY-----"
        static let rsaPrefix = "-----BEGIN RSA PRIVATE KEY-----\n"
        static let rsaSuffix = "\n-----END RSA PRIVATE KEY-----"

        static func stripHeader(_ pemKey: String) -> String? {
            return PEM.stripHeaderFooter(pemKey, header: prefix, footer: suffix) ??
                PEM.stripHeaderFooter(pemKey, header: rsaPrefix, footer: rsaSuffix)
        }

    }

    static func stripHeaderFooter(_ data: String, header: String, footer: String) -> String? {
        guard data.hasPrefix(header) else {
            return nil
        }
        guard let r = data.range(of: footer) else {
            return nil
        }
        return String(data[header.endIndex ..< r.lowerBound])
    }

    static func base64Decode(_ base64Data: String) -> Data? {
        return Data(base64Encoded: base64Data, options: [.ignoreUnknownCharacters])
    }

}
