//
//  RSAKey+JWK.swift
//  JWKTransform
//
//  Created by Gelareh Taban on 2/15/18.
//

import Foundation
import OpenSSL

public class RSAKey {

    /**
     - parameter n: Base64 URL encoded string representing the `modulus` of the RSA Key.
     - parameter e: Base64 URL encoded string representing the `public exponent` of the RSA Key.
     - parameter d: Base64 URL encoded string representing the `private exponent` of the RSA Key.
     */
    private var key: UnsafeMutablePointer<RSA>? = nil
    
    enum keyType {
        case privateKey
        case publicKey
    }
    
    public enum keyFormat {
        case pem
        case der
    }
    
    private var type: keyType
    
    public init(n: String, e: String, d: String? = nil) throws {
        
        key = RSA_new()
        guard key != nil  else {
            throw JWKError.opensslInternal
        }
        type = .publicKey

        if let d = d {
            key?.pointee.d = try base64URLToBignum(d)
            type = .privateKey
        }

        key?.pointee.n = try base64URLToBignum(n)
        key?.pointee.e = try base64URLToBignum(e)

//        #if defined(OPENSSL_1_1_0)
//            if (1 != RSA_set0_key(rsa, rsaModulusBn, rsaExponentBn, NULL); ERR_print_errors_fp(stdout);
//                #else
//                rsa->n = rsaModulusBn;
//                rsa->e = rsaExponentBn;
//        #endif
    }
    
    deinit {
        if let key = key {
            RSA_free(key)
        }
    }

    public func getPublicKey() throws -> String {
        
        //        buf = (char *) malloc (2048);
        //
        //        p = buf;
        //
        //        len = i2d_RSAPublicKey (rsa, &p);
        //        len += i2d_RSAPrivateKey (rsa, &p);
        
        // get size of PK
        var len = i2d_RSAPublicKey (key, nil)
        
        guard len > 0 else {
            
            print("i2d_RSAPublicKey failure: \( ERR_get_error())")
            throw JWKError.createPublicKey
        }
        
        var ber: UnsafeMutablePointer<UInt8>? = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(len))
        // Need to use a throwaway pointer because i2d_RSAPublicKey changes its value (ends up pointing to the end of the value, not the beginning)
        var throwaway = ber
        
        // Encode a PKCS#1 RSAPublicKey structure
        len = i2d_RSAPublicKey (key, &throwaway)
        
        guard len > 0 else {
            print("i2d_RSAPublicKey failure: \( ERR_get_error())")
            throw JWKError.createPublicKey
        }
        let pk = Data(bytes: ber!, count: Int(len))
        
        //
        return pk.base64EncodedString()
    }

    
        public func getPrivateKey() throws -> String {
            
            // get size of PK
            var len = i2d_RSAPrivateKey(key, nil)
            print("key length = ", len)
            
            guard len > 0 else {
                
                print("i2d_RSAPublicKey failure: \( ERR_get_error())")
                throw JWKError.createPrivateKey
            }

            var ber: UnsafeMutablePointer<UInt8>? = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(len))
            // Need to use a throwaway pointer because i2d_RSAPublicKey changes its value (ends up pointing to the end of the value, not the beginning)
            var throwaway = ber
            
            // Encode a PKCS#1 RSAPrivateKey structure
            len = i2d_RSAPrivateKey (key, &throwaway)

            guard len > 0 else {
                print("i2d_RSAPrivateKey failure: \( ERR_get_error())")
                throw JWKError.createPrivateKey
            }
            let pk = Data(bytes: ber!, count: Int(len))
            
            //
            return pk.base64EncodedString()
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

        str = str.replacingOccurrences(of: "-", with: "+")
        str = str.replacingOccurrences(of: "_", with: "/")
        let d = Data(base64Encoded: str)
        
//        let d = Data(base64Encoded: str, options: [.ignoreUnknownCharacters])        
        return d
    }
    
}

extension Data {
    func hexEncodedString() -> String {
        return map { String(format: "%02hhx", $0) }.joined()
    }
    
    public func base64URLEncode() -> String {
        let d = self
        //base64 encoding
        var str = d.base64EncodedString()
        //URL encoding
        str = str.replacingOccurrences(of: "+", with: "-")
        str = str.replacingOccurrences(of: "/", with: "_")

        return str
    }

}

