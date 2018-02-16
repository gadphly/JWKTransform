//
//  RSAKey+JWK.swift
//  JWKTransform
//
//  Created by Gelareh Taban on 2/15/18.
//

import Foundation
import OpenSSL

public class RSAKey {

    private var key: UnsafeMutablePointer<EVP_PKEY>? = nil

    enum keyType {
        case privateKey
        case publicKey
    }
    
    private var type: keyType
    
    /**
     - parameter n: Base64 URL encoded string representing the `modulus` of the RSA Key.
     - parameter e: Base64 URL encoded string representing the `public exponent` of the RSA Key.
     - parameter d: Base64 URL encoded string representing the `private exponent` of the RSA Key.
     */
    public init(n: String, e: String, d: String? = nil) throws {
        
        let rsakey = RSA_new()
        guard rsakey != nil  else {
            throw JWKError.opensslInternal
        }
        type = .publicKey

        if let d = d {
            rsakey?.pointee.d = try base64URLToBignum(d)
            type = .privateKey
        }

        rsakey?.pointee.n = try base64URLToBignum(n)
        rsakey?.pointee.e = try base64URLToBignum(e)
        
        // assign RSAkey to EVP_Pkey to keep
        // EVP_PKEY_assign_RSA but complex macro
        // EVP_PKEY_assign((pkey),EVP_PKEY_RSA,(char *)(rsa))
        
        key = EVP_PKEY_new()
        EVP_PKEY_assign(key, EVP_PKEY_RSA, rsakey)
        guard key != nil else {
            throw JWKError.createKey
        }


//        #if defined(OPENSSL_1_1_0)
//            if (1 != RSA_set0_key(rsa, rsaModulusBn, rsaExponentBn, NULL); ERR_print_errors_fp(stdout);
//                #else
//                rsa->n = rsaModulusBn;
//                rsa->e = rsaExponentBn;
//        #endif
    }
    
    deinit {
        if let key = key {
            EVP_PKEY_free(key)
        }
    }

    public func getPublicKey() throws -> String? {
        
        // Public key can be extracted from only private key too
        guard ( type == keyType.publicKey || type == keyType.privateKey )  else {
            throw JWKError.invalidKeyType
        }

        let bio = BIO_new(BIO_s_mem())

        // writes EVP key to bio
        let  retval = PEM_write_bio_PUBKEY(bio, key)
        
        // get buffer length
        // BIO_PENDING is complex macro
        let publicKeyLen = BIO_ctrl(bio, BIO_CTRL_PENDING, 0, nil)

        guard retval == 1, publicKeyLen > 0 else {
            throw JWKError.createPublicKey
        }

        // read the key from the buffer
        let publicKey: UnsafeMutablePointer<UInt8>? = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(publicKeyLen))
        BIO_read(bio, publicKey, Int32(publicKeyLen));
        
        let pk = Data(bytes: publicKey!, count: Int(publicKeyLen))
        return String(data: pk, encoding: .utf8)
    }

    public func getPrivateKey() throws -> String? {
        
        guard type == keyType.privateKey else {
            throw JWKError.invalidKeyType
        }

        let bio = BIO_new(BIO_s_mem())
        
        // writes EVP key to bio
        let  retval = PEM_write_bio_PrivateKey(bio, key, nil, nil, 0, nil, nil);
        
        // get buffer length
        // BIO_PENDING is complex macro
        let publicKeyLen = BIO_ctrl(bio, BIO_CTRL_PENDING, 0, nil)
        
        guard retval == 1, publicKeyLen > 0 else {
            throw JWKError.createPublicKey
        }
        
        // read the key from the buffer
        let publicKey: UnsafeMutablePointer<UInt8>? = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(publicKeyLen))
        BIO_read(bio, publicKey, Int32(publicKeyLen));
        
        let pk = Data(bytes: publicKey!, count: Int(publicKeyLen))
        return String(data: pk, encoding: .utf8)
    }

    
    // Convert from base64URL to Data to BIGNUM
    private func base64URLToBignum (_ str: String) throws -> UnsafeMutablePointer<BIGNUM> {
        
        guard let data = str.base64URLDecode() else {
            throw JWKError.decoding
        }
        let array = [UInt8](data)
        return array.withUnsafeBufferPointer { p in
            
            // BN_bin2bn() converts the positive integer in big-endian form of length len
            // at s into a BIGNUM and places it in ret.
            // If ret is NULL, a new BIGNUM is created.
            let bn: UnsafeMutablePointer<BIGNUM> = BN_bin2bn(p.baseAddress, Int32(p.count), nil)
            BN_print_fp(stdout, bn);
            print("\n")
            return bn
        }
    }
}

public extension String {
    public func base64URLDecode() -> Data? {
        var str = self
        
        // add padding if necessary
        str = str.padding(toLength: ((str.count+3)/4)*4, withPad: "=", startingAt: 0)

        // URL decode
        str = str.replacingOccurrences(of: "-", with: "+")
        str = str.replacingOccurrences(of: "_", with: "/")
        let d = Data(base64Encoded: str)
        
        return d
    }
    
}

extension Data {
    func hexEncodedString() -> String {
        return map { String(format: "%02hhx", $0) }.joined()
    }
    
    public func base64URLEncode() -> String {
        let d = self
        // base64 encoding
        var str = d.base64EncodedString()

        // URL encode
        str = str.replacingOccurrences(of: "+", with: "-")
        str = str.replacingOccurrences(of: "/", with: "_")

        return str
    }

}

