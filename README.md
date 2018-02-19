# JWKTransform
Library to convert keys of JWK format to more popular formats such as PEM.
**Right now only works for RSA and outputs PEM PKCS#8 format.**


## Build Instructions

swift build -Xlinker -L/usr/local/opt/openssl/lib -Xcc -I/usr/local/opt/openssl/include

#### To build in Xcode:
swift package generate-xcodeproj

Go to targets -> build settings -> search for user paths add to Header Search Paths /usr/local/opt/openssl/include add to Library Search Paths /usr/local/opt/openssl/lib

✨ Build magic ✨


## Usage

Can use either the JWK string or the JWK RSA components as initializer input.

```
let key = try RSAKey(jwk: token)
```
or
```
let key = try RSAKey(n: mod, e: expE, d: expD)
```

Once initialized, can extract public and private keys as PEM format using PKCS#8 encoding.
```
let key = try RSAKey(jwk: token)

let publicPem = try key.getPublicKey(certEncoding.pemPkcs8)
let privatePem = try key.getPublicKey(certEncoding.pemPkcs8)
```

Note that the above should provide the public key that was originally produced. The private key however has fields such as `p`, `q`, etc. that are optional, therefore the produced private key might not be an exact match to the original.

## What's a JWK

JSON Web Key (JWK) defined in https://tools.ietf.org/html/rfc7517

Example JWK:

```
{
	"kty": "RSA",			// key type
	"alg": "RS256",     	// algorithm for the key
	"use": "sig",        	// how the key is meant to be used. For this example, sig represents signature.
	"x5c": [            	// x.509 certificate chain
	"MIIC+DCCAe..="
	],
	// n = modulus and e = exponent for a standard PEM. Both are base64url encoded
    "n": "AJ+E8O4KJ...ltU=",
	"e": "AQAB",
	"kid": "NjVB...TM2Qg",    		// unique identifier for the key
	"x5t": "NjVB...TM2Qg"        	// thumbprint of x.509 cert (SHA-1 thumbprint)
}
```
