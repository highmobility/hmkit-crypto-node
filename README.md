# hm-node-crypto
HMKIT Crypto Node is the HMKit cryptographic layer implementation on pure Node. It is used in [hmkit-node](https://github.com/highmobility/hmkit-node) library.




![Build Status](https://github.com/highmobility/hm-node-crypto/workflows/Node%20CI/badge.svg)



# Table of contents
* [Architecture](#features)
* [Requirements](#requirements)
* [Getting Started](#getting-started)
* [Contributing](#contributing)


## Architecture

**General**: HMKIT Crypto C is pure c cryptography layer implementation based on OpenSSL. 

**Crypto.c**: This contains the OpenSSL implementation.

**Crypto.h**: This is the library header file that is needed to conform to the HMKit Core cryptographic abstraction layer.

**commandline**: This is a test and example application for HMKit Crypto C.

## Requirements

HMKit Crypto C is based on OpenSSL 1.1.0 

## Getting Started

Get an overview by reading the security documentation [browse the documentation](https://high-mobility.com/learn/documentation/security/overview/).

## Contributing

Before starting please read our contribution rules [Contributing](CONTRIBUTE.md)

### Developing

This library supports 8 >= node <= 12 versions. In order to run the test :

```
npm install
npm run test
```

## Licence
This repository is using MIT licence. See more in the [📘 LICENCE](LICENCE.md)
