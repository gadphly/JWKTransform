//
//  JWKError.swift
//  JWKTransform
//
//  Created by Gelareh Taban on 2/15/18.
//

import Foundation

enum JWKError: Error {
    case opensslInternal
    case createKey
    case createPublicKey
    case createPrivateKey
    case decoding
    case encoding
    case invalidKeyType
    case missingAlgorithm
    case signing
    case wrongAlgorithm
    case input
}

