//
//  Utils.swift
//  JWKTransform
//
//  Created by Gelareh Taban on 2/19/18.
//

import Foundation


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
