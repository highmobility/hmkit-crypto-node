# hmkit-crypto-node
HMKIT Crypto Node is the HMKit cryptographic layer implementation using pure JavaScript. It is used in [hmkit-node](https://github.com/highmobility/hmkit-node) library.



![Build Status](https://github.com/highmobility/hmkit-crypto-node/workflows/Node%20CI/badge.svg)



# Table of contents
* [features](#features)
* [Requirements](#requirements)
* [Getting Started](#getting-started)
* [Contributing](#contributing)


## Features

**ECC**: Uses well established *Elliptic Curve Cryptography*'s curve *p256* (that is as secure as RSA, while having a smaller footprint).

**De-/Encrypt**: Enables simple encryption and decryption with *AES128*.

**Keys**: Perform *Diffie-Hellman*'s key exchange using *X9.63 SHA256* algorithm. Additionally
convert keys back and forth between bytes and Apple's `SecKey` format.

**Random**: Create pseudo-random bytes for cryptographic functions or as unique IDs.

**Signatures**: Create and verify *Elliptic Curve Digital Signature Algorithm* (ECDSA) *X9.62 SHA256* or *HMAC* signatures.


## Requirements

HMKit Crypto Node is based on NodeJS >= 8

## Getting Started

Get an overview by reading the security documentation [browse the documentation](https://high-mobility.com/learn/documentation/security/overview/).

## Contributing

Before starting please read our contribution rules [Contributing](CONTRIBUTING.md)

### Developing

This library supports 8 >= node <= 12 versions. In order to run the test :

```
npm install
npm run test
```

## Licence
This repository is using MIT licence. See more in the [LICENCE](LICENCE.md)
