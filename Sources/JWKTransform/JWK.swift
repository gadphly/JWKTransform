//
//  JWK.swift
//  JWKTransform
//
//  Created by Gelareh Taban on 2/19/18.
//

import Foundation

public struct JWK: Codable {
    var kty: String                // key type
    var id: Int?					// key id
    var use: String?				// key usage
    var alg: String?				// Algorithm
    
    var x5u: String?				// (X.509 URL) Header Parameter
    var x5t: String?				// (X.509 Certificate Thumbprint) Header Parameter
    var x5c: String?                // (X.509 Certificate Chain) Header Parameter

    // RSA keys
    // Represented as the base64url encoding of the value’s unsigned big endian representation as an octet sequence.
    var n: String?					// modulus
    var e: String?                  // exponent
    
    var d: String?                  // private exponent
    var p: String?                  // first prime factor
    var q: String?                  // second prime factor
    var dp: String?                 // first factor CRT exponent
    var dq: String?                 // second factor CRT exponent
    var qi: String?                 // first CRT coefficient
    var oth: othType?               // other primes info

    // EC DSS keys
    var crv: String?
    var x: String?
    var y: String?

    enum othType: String, Codable {
        case r
        case d
        case t
    }
}

