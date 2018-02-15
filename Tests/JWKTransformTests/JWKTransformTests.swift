import XCTest
@testable import JWKTransform

class JWKTransformTests: XCTestCase {
    func testExample() {
        // This is an example of a functional test case.
        // Use XCTAssert and related functions to verify your tests produce the correct
        // results.
        XCTAssertEqual(JWKTransform().text, "Hello, World!")
    }


    func testJWKtoPEM() {
        
        let exp = "AQAB"
        let mod = "AJ-E8O4KJT6So_lUkCIkU0QKW7QjMp9vG7S7vZx0M399idZ4mP7iWWW6OTvjLHpDTx7uapiwRQktDNx3GHigJDmbbu8_VtS5K6J6be1gVrvu6pxmZtrz8PazlH5WYxkuUIfUYpzyfUubZzqzuVWqQO0W9kOhFN7HILAxb1WsQREX-iLg14MGGafrQnJgXHBAwSH0OOJr7v-nRz8AFCAicN8v0uIar9lRA7JRHQCZtpI_lkSGKKBQT1Zae9-9YlWbZlfXErQS1uYoAb3j3uaLbJVO7SNjQqEsRTjYxfpBsTtkvJmwcwA0wV2gBO3JR6K6ep0Y_KyMR8w9Fd_lvJqdltU"
        
        do {
            var k = try RSAKey(n: mod, e: exp)
        	XCTAssertNotNil(k)
        
            let pem = try k.getPublicKey()
            print(pem.data(using: .utf8)?.hexEncodedString())
        
        } catch {
        	XCTFail()
        }
    }
    
    static var allTests = [
        ("testExample", testExample),
    ]
}
