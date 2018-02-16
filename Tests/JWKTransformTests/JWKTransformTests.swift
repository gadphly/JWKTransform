import XCTest
@testable import JWKTransform

class JWKTransformTests: XCTestCase {

    func testJWKtoPEM_opensslGenerated() {
        
        let expE = "AQAB"
        let mod = "ALPElc5pCLJZ8WJq9H2v4vPH00v2usB97Tc0YxNTNklB489BOyCdvtiY6sLHn7tEHGA5x_6IsJyxp_5vnrcNbaACAt9FHniorJDNaakYumfC00WSEt1mB0RRqmtyH1RAX_7I5cYzanxvMvXOHyf6UWBsacwm43l7A3n7NM30l5pUHFi9TMCCAxzdGZwHJqY0rDs6NMD0Bm_5_DCH0_q1K_dG8XIffudcDhFV0ThOZ0KY5FvZ-mghAnskgyCtJ7yC7IFzFlDVt6ACBd-bSvcmlJBsV1TY7vkRiS4qZyCA1OWqSWPJZik1ZswTIJWNn4F6TSm4EJjAZVCeC9V9OalM8Oc"
        let expD = "QcTVbgv9c4r2hiRNSMKVzMy54FvnXU90_zJ6YPKbtNeXahcac8disEnZ8eMo7FFx9D6Pje8idmGE7dCWh7AxAE5cEKVwDYLgh6WvV39Fi3q64wQbRMb0N6mNKPw6vA9FT6jeb9IVzmq8gTOlMHIjXZysZFWB-crorbMbUZJ_-KTaHoPf2yYMhJAmUhrtRrSICASnzL010aay5kyAx0pQmrLQRtl8jtYjLqMt1Eie1Rcm_OlZtfMm2bWmXAWkaH9K6WJlI6pAAeCeZ9FKjBumMjmTnwNgx480pPhWxojR5J5WWbVI8EGuUVJZ1LrNT47uofM3lPXWJqCc4L7VXni9MQ"
        
        let expectedPublicKey = """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs8SVzmkIslnxYmr0fa/i
88fTS/a6wH3tNzRjE1M2SUHjz0E7IJ2+2Jjqwsefu0QcYDnH/oiwnLGn/m+etw1t
oAIC30UeeKiskM1pqRi6Z8LTRZIS3WYHRFGqa3IfVEBf/sjlxjNqfG8y9c4fJ/pR
YGxpzCbjeXsDefs0zfSXmlQcWL1MwIIDHN0ZnAcmpjSsOzo0wPQGb/n8MIfT+rUr
90bxch9+51wOEVXROE5nQpjkW9n6aCECeySDIK0nvILsgXMWUNW3oAIF35tK9yaU
kGxXVNju+RGJLipnIIDU5apJY8lmKTVmzBMglY2fgXpNKbgQmMBlUJ4L1X05qUzw
5wIDAQAB
-----END PUBLIC KEY-----\n
"""
        // expected private key is a truncated version of the original
        // private key because it is missing a bunch of parameters
        let expectedPrivateKey = """
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCzxJXOaQiyWfFi
avR9r+Lzx9NL9rrAfe03NGMTUzZJQePPQTsgnb7YmOrCx5+7RBxgOcf+iLCcsaf+
b563DW2gAgLfRR54qKyQzWmpGLpnwtNFkhLdZgdEUaprch9UQF/+yOXGM2p8bzL1
zh8n+lFgbGnMJuN5ewN5+zTN9JeaVBxYvUzAggMc3RmcByamNKw7OjTA9AZv+fww
h9P6tSv3RvFyH37nXA4RVdE4TmdCmORb2fpoIQJ7JIMgrSe8guyBcxZQ1begAgXf
m0r3JpSQbFdU2O75EYkuKmcggNTlqkljyWYpNWbMEyCVjZ+Bek0puBCYwGVQngvV
fTmpTPDnAgMBAAECggEAQcTVbgv9c4r2hiRNSMKVzMy54FvnXU90/zJ6YPKbtNeX
ahcac8disEnZ8eMo7FFx9D6Pje8idmGE7dCWh7AxAE5cEKVwDYLgh6WvV39Fi3q6
4wQbRMb0N6mNKPw6vA9FT6jeb9IVzmq8gTOlMHIjXZysZFWB+crorbMbUZJ/+KTa
HoPf2yYMhJAmUhrtRrSICASnzL010aay5kyAx0pQmrLQRtl8jtYjLqMt1Eie1Rcm
/OlZtfMm2bWmXAWkaH9K6WJlI6pAAeCeZ9FKjBumMjmTnwNgx480pPhWxojR5J5W
WbVI8EGuUVJZ1LrNT47uofM3lPXWJqCc4L7VXni9MQ
-----END PRIVATE KEY-----\n
"""
        do {
            let k = try RSAKey(n: mod, e: expE, d: expD)
        	XCTAssertNotNil(k)
        
            let publicPem = try k.getPublicKey()
            XCTAssertNotNil(publicPem)
//            print("\n\npublicPemPKCS1: \n", publicPem ?? "nil")
            XCTAssertEqual(publicPem, expectedPublicKey, "Does not match expected public key")

            let privatePem = try k.getPrivateKey()
            XCTAssertNotNil(privatePem)
//            print("\n\nprivatePem: \n", privatePem ?? "nil")
            XCTAssertEqual(publicPem, expectedPrivateKey, "Does not match expected private key")
        } catch {
        	XCTFail()
        }
    }

    func testJWKtoPEM_appIDGenerated() {
        
        let expE = "AQAB"
        let mod = "AJ-E8O4KJT6So_lUkCIkU0QKW7QjMp9vG7S7vZx0M399idZ4mP7iWWW6OTvjLHpDTx7uapiwRQktDNx3GHigJDmbbu8_VtS5K6J6be1gVrvu6pxmZtrz8PazlH5WYxkuUIfUYpzyfUubZzqzuVWqQO0W9kOhFN7HILAxb1WsQREX-iLg14MGGafrQnJgXHBAwSH0OOJr7v-nRz8AFCAicN8v0uIar9lRA7JRHQCZtpI_lkSGKKBQT1Zae9-9YlWbZlfXErQS1uYoAb3j3uaLbJVO7SNjQqEsRTjYxfpBsTtkvJmwcwA0wV2gBO3JR6K6ep0Y_KyMR8w9Fd_lvJqdltU"
        
        do {
            let k = try RSAKey(n: mod, e: expE)
            XCTAssertNotNil(k)
            
            let publicPem = try k.getPublicKey()
            XCTAssertNotNil(publicPem)
            print("\n\nPublic Key (PEM PKCS#8): \n", publicPem ?? "nil")
            
        } catch {
            XCTFail()
        }
    }

    static var allTests = [
        ("testJWKtoPEM_opensslGenerated", testJWKtoPEM_opensslGenerated),
    ]
}

/*

 private key:
 (PKCS#1, which can only contain RSA keys)
 
 -----BEGIN RSA PRIVATE KEY-----
 MIIEowIBAAKCAQEAs8SVzmkIslnxYmr0fa/i88fTS/a6wH3tNzRjE1M2SUHjz0E7
 IJ2+2Jjqwsefu0QcYDnH/oiwnLGn/m+etw1toAIC30UeeKiskM1pqRi6Z8LTRZIS
 3WYHRFGqa3IfVEBf/sjlxjNqfG8y9c4fJ/pRYGxpzCbjeXsDefs0zfSXmlQcWL1M
 wIIDHN0ZnAcmpjSsOzo0wPQGb/n8MIfT+rUr90bxch9+51wOEVXROE5nQpjkW9n6
 aCECeySDIK0nvILsgXMWUNW3oAIF35tK9yaUkGxXVNju+RGJLipnIIDU5apJY8lm
 KTVmzBMglY2fgXpNKbgQmMBlUJ4L1X05qUzw5wIDAQABAoIBAEHE1W4L/XOK9oYk
 TUjClczMueBb511PdP8yemDym7TXl2oXGnPHYrBJ2fHjKOxRcfQ+j43vInZhhO3Q
 loewMQBOXBClcA2C4Ielr1d/RYt6uuMEG0TG9DepjSj8OrwPRU+o3m/SFc5qvIEz
 pTByI12crGRVgfnK6K2zG1GSf/ik2h6D39smDISQJlIa7Ua0iAgEp8y9NdGmsuZM
 gMdKUJqy0EbZfI7WIy6jLdRIntUXJvzpWbXzJtm1plwFpGh/SuliZSOqQAHgnmfR
 SowbpjI5k58DYMePNKT4VsaI0eSeVlm1SPBBrlFSWdS6zU+O7qHzN5T11iagnOC+
 1V54vTECgYEA3eJAAca3Y9EhNc0QOjTLxoeRmC9v1X5XdVDS40XsDmcMYvXXjfUr
 ZgSrQa8Hm4l/bkhJJMbacxoaQaoVJyDsBU6S2Si4h3SC8RatUcgEM18RZVALSCZU
 BBklvIhuK3E04jVeoWnd4y8x4atlN5IF/Q5+qy0/8nTJuGKykyGv8c8CgYEAz2iT
 1qlPXyc2Oh4nB5Ztud4EadwP95mIxK60yjqWZr4ii2SMfkMU3UE/Ad7FuLXoQCWQ
 Ot15M+afw3q3C9PkVprdm1ZEHqBb60zrr0OA888vADvtnB1s5Xtgua6NVb5MLgx6
 phwQaRdj4ECfj0wYX0IUPCFmTLy66NivMDSAzWkCgYAfaW5iUf2YdfzbnwJTGzJW
 Es872ktc0BwVkbGpVzbJ+zC3udIgWLsiIDsWe276SAbwV+9y82vtq55X+XoxJeoD
 /lGvyKIHGymGdA1pbIWbuDPAQgq21iZCxkSfYjkmkUpJVADnnRM6nG3VYuxbZ6LN
 ZoXsOeW5r2r3XZGmXriH5QKBgQCMOVPaSVWUK1qKKGCSzK0agHPTbiiNaYwCDWvF
 XZ7Zj6qjOzORGaE9hSMoDIj4vGNtGvhME/ghksZozsp6gKNbuhAhOU2MtzXt+29M
 awL/0w8fxWR7q5k3/RYD83MyiRnP+Dfjng2qP1oS/x3hL706id5MWPhk4SQs0HKA
 0L5UIQKBgGOaN3YPwxbXWZ9oTVEbJub3gv6QIxUsVZicnOUHdHTjr9jYzlo5XLse
 0OxLWjoRmv4adEPnc3NaDIPlpzJyB6IiY3VmBcXRgFgzeCSj5f+9ZNpI1jEby/45
 vzfEVFCvRLxCvBT7yW9FOXy+i+/SQyLjNQnFEFo7KRLQSCgrAz6p
 -----END RSA PRIVATE KEY-----

 openssl pkcs8 -nocrypt -topk8 -in privateKeyPKCS1.pem -out privateKey.pem
 
 PKCS#8
 -----BEGIN PRIVATE KEY-----
 MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCzxJXOaQiyWfFi
 avR9r+Lzx9NL9rrAfe03NGMTUzZJQePPQTsgnb7YmOrCx5+7RBxgOcf+iLCcsaf+
 b563DW2gAgLfRR54qKyQzWmpGLpnwtNFkhLdZgdEUaprch9UQF/+yOXGM2p8bzL1
 zh8n+lFgbGnMJuN5ewN5+zTN9JeaVBxYvUzAggMc3RmcByamNKw7OjTA9AZv+fww
 h9P6tSv3RvFyH37nXA4RVdE4TmdCmORb2fpoIQJ7JIMgrSe8guyBcxZQ1begAgXf
 m0r3JpSQbFdU2O75EYkuKmcggNTlqkljyWYpNWbMEyCVjZ+Bek0puBCYwGVQngvV
 fTmpTPDnAgMBAAECggEAQcTVbgv9c4r2hiRNSMKVzMy54FvnXU90/zJ6YPKbtNeX
 ahcac8disEnZ8eMo7FFx9D6Pje8idmGE7dCWh7AxAE5cEKVwDYLgh6WvV39Fi3q6
 4wQbRMb0N6mNKPw6vA9FT6jeb9IVzmq8gTOlMHIjXZysZFWB+crorbMbUZJ/+KTa
 HoPf2yYMhJAmUhrtRrSICASnzL010aay5kyAx0pQmrLQRtl8jtYjLqMt1Eie1Rcm
 /OlZtfMm2bWmXAWkaH9K6WJlI6pAAeCeZ9FKjBumMjmTnwNgx480pPhWxojR5J5W
 WbVI8EGuUVJZ1LrNT47uofM3lPXWJqCc4L7VXni9MQKBgQDd4kABxrdj0SE1zRA6
 NMvGh5GYL2/Vfld1UNLjRewOZwxi9deN9StmBKtBrwebiX9uSEkkxtpzGhpBqhUn
 IOwFTpLZKLiHdILxFq1RyAQzXxFlUAtIJlQEGSW8iG4rcTTiNV6had3jLzHhq2U3
 kgX9Dn6rLT/ydMm4YrKTIa/xzwKBgQDPaJPWqU9fJzY6HicHlm253gRp3A/3mYjE
 rrTKOpZmviKLZIx+QxTdQT8B3sW4tehAJZA63Xkz5p/DercL0+RWmt2bVkQeoFvr
 TOuvQ4Dzzy8AO+2cHWzle2C5ro1VvkwuDHqmHBBpF2PgQJ+PTBhfQhQ8IWZMvLro
 2K8wNIDNaQKBgB9pbmJR/Zh1/NufAlMbMlYSzzvaS1zQHBWRsalXNsn7MLe50iBY
 uyIgOxZ7bvpIBvBX73Lza+2rnlf5ejEl6gP+Ua/IogcbKYZ0DWlshZu4M8BCCrbW
 JkLGRJ9iOSaRSklUAOedEzqcbdVi7Ftnos1mhew55bmvavddkaZeuIflAoGBAIw5
 U9pJVZQrWoooYJLMrRqAc9NuKI1pjAINa8VdntmPqqM7M5EZoT2FIygMiPi8Y20a
 +EwT+CGSxmjOynqAo1u6ECE5TYy3Ne37b0xrAv/TDx/FZHurmTf9FgPzczKJGc/4
 N+OeDao/WhL/HeEvvTqJ3kxY+GThJCzQcoDQvlQhAoGAY5o3dg/DFtdZn2hNURsm
 5veC/pAjFSxVmJyc5Qd0dOOv2NjOWjlcux7Q7EtaOhGa/hp0Q+dzc1oMg+WnMnIH
 oiJjdWYFxdGAWDN4JKPl/71k2kjWMRvL/jm/N8RUUK9EvEK8FPvJb0U5fL6L79JD
 IuM1CcUQWjspEtBIKCsDPqk=
 -----END PRIVATE KEY-----

 -----BEGIN PUBLIC KEY-----
 MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs8SVzmkIslnxYmr0fa/i
 88fTS/a6wH3tNzRjE1M2SUHjz0E7IJ2+2Jjqwsefu0QcYDnH/oiwnLGn/m+etw1t
 oAIC30UeeKiskM1pqRi6Z8LTRZIS3WYHRFGqa3IfVEBf/sjlxjNqfG8y9c4fJ/pR
 YGxpzCbjeXsDefs0zfSXmlQcWL1MwIIDHN0ZnAcmpjSsOzo0wPQGb/n8MIfT+rUr
 90bxch9+51wOEVXROE5nQpjkW9n6aCECeySDIK0nvILsgXMWUNW3oAIF35tK9yaU
 kGxXVNju+RGJLipnIIDU5apJY8lmKTVmzBMglY2fgXpNKbgQmMBlUJ4L1X05qUzw
 5wIDAQAB
 -----END PUBLIC KEY-----
 
 
{
    kty: 'RSA',
    use: 'sig',
    n: 'ALPElc5pCLJZ8WJq9H2v4vPH00v2usB97Tc0YxNTNklB489BOyCdvtiY6sLHn7tEHGA5x_6IsJyxp_5vnrcNbaACAt9FHniorJDNaakYumfC00WSEt1mB0RRqmtyH1RAX_7I5cYzanxvMvXOHyf6UWBsacwm43l7A3n7NM30l5pUHFi9TMCCAxzdGZwHJqY0rDs6NMD0Bm_5_DCH0_q1K_dG8XIffudcDhFV0ThOZ0KY5FvZ-mghAnskgyCtJ7yC7IFzFlDVt6ACBd-bSvcmlJBsV1TY7vkRiS4qZyCA1OWqSWPJZik1ZswTIJWNn4F6TSm4EJjAZVCeC9V9OalM8Oc',
    e: 'AQAB',
    d: 'QcTVbgv9c4r2hiRNSMKVzMy54FvnXU90_zJ6YPKbtNeXahcac8disEnZ8eMo7FFx9D6Pje8idmGE7dCWh7AxAE5cEKVwDYLgh6WvV39Fi3q64wQbRMb0N6mNKPw6vA9FT6jeb9IVzmq8gTOlMHIjXZysZFWB-crorbMbUZJ_-KTaHoPf2yYMhJAmUhrtRrSICASnzL010aay5kyAx0pQmrLQRtl8jtYjLqMt1Eie1Rcm_OlZtfMm2bWmXAWkaH9K6WJlI6pAAeCeZ9FKjBumMjmTnwNgx480pPhWxojR5J5WWbVI8EGuUVJZ1LrNT47uofM3lPXWJqCc4L7VXni9MQ',
    p: 'AN3iQAHGt2PRITXNEDo0y8aHkZgvb9V-V3VQ0uNF7A5nDGL11431K2YEq0GvB5uJf25ISSTG2nMaGkGqFScg7AVOktkouId0gvEWrVHIBDNfEWVQC0gmVAQZJbyIbitxNOI1XqFp3eMvMeGrZTeSBf0OfqstP_J0ybhispMhr_HP',
    q: 'AM9ok9apT18nNjoeJweWbbneBGncD_eZiMSutMo6lma-IotkjH5DFN1BPwHexbi16EAlkDrdeTPmn8N6twvT5Faa3ZtWRB6gW-tM669DgPPPLwA77ZwdbOV7YLmujVW-TC4MeqYcEGkXY-BAn49MGF9CFDwhZky8uujYrzA0gM1p',
    dp: 'H2luYlH9mHX8258CUxsyVhLPO9pLXNAcFZGxqVc2yfswt7nSIFi7IiA7Fntu-kgG8FfvcvNr7aueV_l6MSXqA_5Rr8iiBxsphnQNaWyFm7gzwEIKttYmQsZEn2I5JpFKSVQA550TOpxt1WLsW2eizWaF7Dnlua9q912Rpl64h-U',
    dq: 'AIw5U9pJVZQrWoooYJLMrRqAc9NuKI1pjAINa8VdntmPqqM7M5EZoT2FIygMiPi8Y20a-EwT-CGSxmjOynqAo1u6ECE5TYy3Ne37b0xrAv_TDx_FZHurmTf9FgPzczKJGc_4N-OeDao_WhL_HeEvvTqJ3kxY-GThJCzQcoDQvlQh',
    qi: 'Y5o3dg_DFtdZn2hNURsm5veC_pAjFSxVmJyc5Qd0dOOv2NjOWjlcux7Q7EtaOhGa_hp0Q-dzc1oMg-WnMnIHoiJjdWYFxdGAWDN4JKPl_71k2kjWMRvL_jm_N8RUUK9EvEK8FPvJb0U5fL6L79JDIuM1CcUQWjspEtBIKCsDPqk'
    
}

*/
