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
    public init(n: String, e: String, d: String? = nil, p: String? = nil, q: String? = nil) throws {
        
        let rsakey = RSA_new()
        guard rsakey != nil  else {
            throw JWKError.opensslInternal
        }
        type = .publicKey
        
        if let d = d {
            rsakey?.pointee.d = try base64URLToBignum(d)
            type = .privateKey
        }
        if let p = p {
            rsakey?.pointee.p = try base64URLToBignum(p)
        }
        if let q = q {
            rsakey?.pointee.q = try base64URLToBignum(q)
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
    }

    public convenience init(jwk: String) throws {

        if let jwkData = jwk.data(using: .utf8) {
            let jwkJSON = try? JSONDecoder().decode(JWK.self, from: jwkData)
            
            guard jwkJSON?.kty == "RSA", let modulus = jwkJSON?.n, let exp = jwkJSON?.e else {
                throw JWKError.input
            }

            if let privExp = jwkJSON?.d {
                try self.init(n: modulus, e: exp, d: privExp)
            } else {
                try self.init(n: modulus, e: exp)
            }
        } else {
            throw JWKError.input
        }
    }
    

//        #if defined(OPENSSL_1_1_0)
//            if (1 != RSA_set0_key(rsa, rsaModulusBn, rsaExponentBn, NULL); ERR_print_errors_fp(stdout);
//                #else
//                rsa->n = rsaModulusBn;
//                rsa->e = rsaExponentBn;
//        #endif
    
    deinit {
        if let key = key {
            EVP_PKEY_free(key)
        }
    }
    public func getPublicKey(_ encoding: certEncoding? = certEncoding.pemPkcs8) throws -> String? {

        // currently only support PEM PKCS#8
        guard encoding == certEncoding.pemPkcs8 else {
            throw JWKError.invalidKeyType
        }
        
        // PEM PKCS#8
        return try getPublicPEM()
    }

    public func getPrivateKey(_ encoding: certEncoding? = certEncoding.pemPkcs8) throws -> String? {
        
        // currently only support PEM PKCS#8
        guard encoding == certEncoding.pemPkcs8 else {
            throw JWKError.invalidKeyType
        }
        
        // PEM PKCS#8
        return try getPublicPEM()
    }

    private func getPublicPEM() throws -> String? {
        
        // Public key can be extracted from both public and private keys
        guard ( type == keyType.publicKey || type == keyType.privateKey )  else {
            throw JWKError.invalidKeyType
        }

        let bio = BIO_new(BIO_s_mem())

        // writes EVP key to bio
        let  retval = PEM_write_bio_PUBKEY(bio, key)
        
        // get length of BIO that was created
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

    private func getPrivatePEM() throws -> String? {
        
        guard type == keyType.privateKey else {
            throw JWKError.invalidKeyType
        }

        let bio = BIO_new(BIO_s_mem())
        
        // writes EVP key to bio
        let  retval = PEM_write_bio_PrivateKey(bio, key, nil, nil, 0, nil, nil);
        
        // get length of BIO that was created
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
			// BN_print_fp(stdout, bn);
            return bn
        }
    }
}

