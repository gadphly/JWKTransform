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
    case decoding
    case encoding
    case incorrectNumberOfSegments
    case missingAlgorithm
    case signing
    case wrongAlgorithm
}

