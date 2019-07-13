/*
  * Copyright (C) 2018 High-Mobility GmbH
  *
  * This program is free software: you can redistribute it and/or modify
  * it under the terms of the GNU General Public License as published by
  * the Free Software Foundation, either version 3 of the License, or
  * (at your option) any later version.
  *
  * This program is distributed in the hope that it will be useful,
  * but WITHOUT ANY WARRANTY; without even the implied warranty of
  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
  * GNU General Public License for more details.
  *
  * You should have received a copy of the GNU General Public License
  * along with this program. If not, see http://www.gnu.org/licenses/.
  *
  * Please inquire about commercial licensing options at
  * licensing@high-mobility.com*
*/

const crypto = require('crypto')
const hmcrypto = require('../src/HmCrypto')

const REPEATE_TEST = 1000

describe(`generateKeys`, () => {
  it(`generates publicKey and privateKey repeatedly`, () => {
    for (var i = 0; i < REPEATE_TEST; i++) {
      const keys = hmcrypto.generateKeys()
      expect(keys.publicKey.length).toBe(64)
      expect(keys.privateKey.length).toBe(32)
    }
  })
})

describe(`hmac`, () => {
  const key = Buffer.from([115, 228, 83, 59, 244, 133, 161, 194, 199, 241, 63, 123, 104, 1, 218, 147, 81, 95, 75, 191, 203, 174, 87, 44, 223, 32, 113, 121, 205, 50, 151, 177])
  it(`generates HMAC for shorter than 64 bytes message`, () => {
    const message = Buffer.from([40, 175, 134, 252, 218, 233, 81, 240, 96])

    const expectedHmac = Buffer.from([185, 190, 231, 253, 176, 49, 208, 104, 185, 136, 191, 50, 64, 151, 1, 163, 172, 2, 184, 146, 234, 32, 241, 103, 193, 98, 79, 87, 17, 12, 169, 142])
    expect(hmcrypto.hmac(key, message)).toStrictEqual(expectedHmac)
  })

  it(`generates HMAC for 64 bytes message`, () => {
    const message = Buffer.from([220, 22, 86, 177, 5, 200, 2, 59, 165, 163, 100, 103, 168, 103, 243, 237, 83, 174, 251, 173, 128, 185, 196, 192, 80, 2, 1, 111, 232, 199, 123, 110, 17, 165, 112, 116, 182, 78, 200, 235, 162, 26, 50, 12, 39, 127, 72, 32, 81, 51, 143, 242, 100, 196, 139, 224, 194, 200, 44, 81, 41, 105, 234, 171])
    const expectedHmac = Buffer.from([39, 74, 0, 61, 144, 173, 182, 249, 193, 113, 169, 71, 188, 26, 153, 70, 87, 8, 245, 150, 9, 101, 216, 51, 210, 112, 7, 167, 223, 118, 117, 247])
    expect(hmcrypto.hmac(key, message)).toStrictEqual(expectedHmac)
  })

  it(`generates HMAC for longer than 64 bytes message`, () => {
    const message = Buffer.from([89, 79, 214, 77, 48, 4, 79, 74, 153, 146, 146, 4, 31, 28, 105, 138, 108, 113, 70, 159, 2, 174, 50, 189, 55, 210, 232, 116, 124, 67, 106, 173, 113, 79, 233, 92, 200, 31, 69, 141, 236, 254, 29, 149, 132, 128, 95, 39, 28, 92, 114, 253, 202, 133, 104, 112, 221, 11, 210, 202, 206, 1, 241, 107, 145, 82, 103, 33])
    const expectedHmac = Buffer.from([224, 51, 67, 97, 111, 67, 10, 108, 59, 81, 253, 114, 111, 237, 252, 150, 0, 104, 142, 114, 12, 238, 163, 142, 218, 236, 14, 177, 132, 22, 53, 150])
    expect(hmcrypto.hmac(key, message)).toStrictEqual(expectedHmac)
  })
})

describe(`computeSecret`, () => {
  it(`computes secret for alice and bob`, () => {
    const alicePrivateKey = Buffer.from([244, 145, 90, 152, 245, 52, 72, 93, 249, 203, 119, 56, 76, 235, 117, 126, 179, 112, 106, 102, 84, 65, 197, 18, 15, 151, 111, 56, 235, 187, 198, 156])
    const BobPublicKey = Buffer.from([185, 228, 221, 236, 81, 145, 148, 124, 1, 154, 57, 252, 62, 252, 46, 67, 34, 17, 158, 148, 37, 166, 10, 81, 22, 36, 76, 203, 146, 96, 249, 11, 52, 219, 120, 114, 83, 20, 22, 125, 66, 30, 247, 152, 101, 247, 92, 24, 71, 22, 113, 68, 115, 112, 240, 17, 48, 178, 17, 110, 88, 59, 66, 134])

    const expectedSharedKey = Buffer.from([128, 242, 182, 173, 146, 232, 192, 21, 138, 213, 49, 62, 86, 109, 73, 37, 150, 167, 194, 14, 54, 203, 41, 211, 223, 3, 135, 246, 229, 246, 106, 255])
    expect(hmcrypto.computeSecret(alicePrivateKey, BobPublicKey)).toStrictEqual(expectedSharedKey)
  })
})

describe(`keyPairToPem`, () => {
  it(`create pem from key pair`, () => {
    const privateKey = Buffer.from([208, 190, 220, 213, 160, 253, 60, 60, 235, 211, 139, 223, 161, 146, 33, 8, 190, 67, 27, 136, 4, 79, 117, 224, 95, 221, 32, 56, 106, 38, 5, 73])
    const publicKey = Buffer.from([160, 174, 8, 133, 165, 201, 213, 60, 113, 227, 43, 171, 107, 32, 213, 162, 237, 19, 147, 238, 31, 138, 129, 56, 171, 197, 102, 150, 205, 107, 217, 120, 102, 115, 234, 177, 217, 239, 186, 178, 134, 116, 222, 0, 2, 214, 44, 56, 227, 3, 15, 166, 210, 182, 80, 55, 160, 37, 103, 137, 150, 126, 192, 27])

    const expectedPem = `-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg0L7c1aD9PDzr04vf\noZIhCL5DG4gET3XgX90gOGomBUmhRANCAASgrgiFpcnVPHHjK6trINWi7ROT7h+K\ngTirxWaWzWvZeGZz6rHZ77qyhnTeAALWLDjjAw+m0rZQN6AlZ4mWfsAb\n-----END PRIVATE KEY-----\n\n`
    expect(hmcrypto.keyPairToPem(privateKey, publicKey)).toBe(expectedPem)
  })

  it(`is able to sign using key pair repeatedly`, () => {
    for (var i = 0; i < REPEATE_TEST; i++) {
      const keys = hmcrypto.generateKeys()
      const pem = hmcrypto.keyPairToPem(keys.privateKey, keys.publicKey)
      crypto.createSign('SHA256').update('blah blah').sign(pem)
    }
  })
})

describe(`publicKeyToPem`, () => {
  it(`converts publickey to pem`, () => {
    const publicKey = Buffer.from([160, 174, 8, 133, 165, 201, 213, 60, 113, 227, 43, 171, 107, 32, 213, 162, 237, 19, 147, 238, 31, 138, 129, 56, 171, 197, 102, 150, 205, 107, 217, 120, 102, 115, 234, 177, 217, 239, 186, 178, 134, 116, 222, 0, 2, 214, 44, 56, 227, 3, 15, 166, 210, 182, 80, 55, 160, 37, 103, 137, 150, 126, 192, 27])
    const expectedPem = `-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEoK4IhaXJ1Txx4yurayDVou0Tk+4f\nioE4q8Vmls1r2Xhmc+qx2e+6soZ03gAC1iw44wMPptK2UDegJWeJln7AGw==\n-----END PUBLIC KEY-----\n\n`
    expect(hmcrypto.publicKeyToPem(publicKey)).toBe(expectedPem)
  })
})

describe(`sign`, () => {
  const privateKey = Buffer.from([208, 190, 220, 213, 160, 253, 60, 60, 235, 211, 139, 223, 161, 146, 33, 8, 190, 67, 27, 136, 4, 79, 117, 224, 95, 221, 32, 56, 106, 38, 5, 73])
  const publicKey = Buffer.from([160, 174, 8, 133, 165, 201, 213, 60, 113, 227, 43, 171, 107, 32, 213, 162, 237, 19, 147, 238, 31, 138, 129, 56, 171, 197, 102, 150, 205, 107, 217, 120, 102, 115, 234, 177, 217, 239, 186, 178, 134, 116, 222, 0, 2, 214, 44, 56, 227, 3, 15, 166, 210, 182, 80, 55, 160, 37, 103, 137, 150, 126, 192, 27])

  it(`should be 64 bytes long`, () => {
    const message = Buffer.from([1, 6, 0, 4])
    for (var i = 0; i < REPEATE_TEST; i++) {
      expect(hmcrypto.sign(message, privateKey, publicKey).length).toBe(64)
    }
  })
})

describe(`verify`, () => {
  const publicKey = Buffer.from([160, 174, 8, 133, 165, 201, 213, 60, 113, 227, 43, 171, 107, 32, 213, 162, 237, 19, 147, 238, 31, 138, 129, 56, 171, 197, 102, 150, 205, 107, 217, 120, 102, 115, 234, 177, 217, 239, 186, 178, 134, 116, 222, 0, 2, 214, 44, 56, 227, 3, 15, 166, 210, 182, 80, 55, 160, 37, 103, 137, 150, 126, 192, 27])
  it(`should verify the message`, () => {
    const message = Buffer.from([1, 6, 0, 4])
    const signature = Buffer.from([162, 188, 75, 44, 80, 153, 203, 165, 5, 38, 78, 232, 84, 228, 111, 142, 132, 134, 35, 215, 71, 207, 129, 146, 147, 231, 42, 234, 200, 174, 157, 22, 107, 225, 130, 195, 170, 145, 231, 219, 178, 80, 197, 175, 143, 104, 218, 18, 41, 73, 233, 212, 85, 105, 134, 200, 135, 22, 33, 72, 204, 162, 126, 16])
    // A2BC4B2C5099CBA505264EE854E46F8E848623D747CF819293E72AEAC8AE9D166BE182C3AA91E7DBB250C5AF8F68DA122949E9D4556986C887162148CCA27E10
    expect(hmcrypto.verify(message, signature, publicKey)).toBe(true)
  })

  it(`when one part of signature starts with 0`, () => {
    const message = Buffer.from([105, 145, 52, 58, 4, 195, 224, 164, 131])
    const signature = Buffer.from([171, 160, 108, 219, 54, 76, 104, 72, 212, 211, 7, 13, 94, 54, 189, 84, 204, 73, 59, 35, 218, 87, 197, 67, 134, 238, 91, 89, 71, 105, 71, 85, 0, 143, 214, 153, 35, 117, 199, 198, 38, 233, 75, 22, 146, 27, 15, 96, 231, 95, 161, 178, 67, 107, 81, 0, 255, 39, 246, 77, 70, 100, 186, 182])
    expect(hmcrypto.verify(message, signature, publicKey)).toBe(true)
  })
})

describe(`sign & verify`, () => {
  const privateKey = Buffer.from([208, 190, 220, 213, 160, 253, 60, 60, 235, 211, 139, 223, 161, 146, 33, 8, 190, 67, 27, 136, 4, 79, 117, 224, 95, 221, 32, 56, 106, 38, 5, 73])
  const publicKey = Buffer.from([160, 174, 8, 133, 165, 201, 213, 60, 113, 227, 43, 171, 107, 32, 213, 162, 237, 19, 147, 238, 31, 138, 129, 56, 171, 197, 102, 150, 205, 107, 217, 120, 102, 115, 234, 177, 217, 239, 186, 178, 134, 116, 222, 0, 2, 214, 44, 56, 227, 3, 15, 166, 210, 182, 80, 55, 160, 37, 103, 137, 150, 126, 192, 27])
  it(`sign and verify repeatedly`, () => {
    for (var i = 0; i < REPEATE_TEST; i++) {
      const randomSize = Math.floor(Math.random() * (1000 - 1) + 1)
      const message = crypto.randomBytes(randomSize)
      const signature = hmcrypto.sign(message, privateKey, publicKey)
      if (hmcrypto.verify(message, signature, publicKey) === false) {
        console.log(`message: ${message.toString('hex')} | signature: ${signature.toString('hex')}`)
      }
      expect(hmcrypto.verify(message, signature, publicKey)).toBe(true)
    }
  })
})
