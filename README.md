# lua-resty-nettle

LuaJIT FFI bindings for [Nettle](http://www.lysator.liu.se/~nisse/nettle/nettle.html) (a low-level cryptographic library)

## Status

All the bindings that do not depend on [GMP](https://gmplib.org/) are ready to use. The [GMP](https://gmplib.org/) depended functionality is the [public-key algorithms](http://www.lysator.liu.se/~nisse/nettle/nettle.html#Public_002dkey-algorithms) (i.e. RSA, DSA, and ECDSA). Much of the documentation here is copied from [Nettle's documentation](http://www.lysator.liu.se/~nisse/nettle/nettle.html), but I have included Lua examples to it. I will be adding more documentation shortly.

## Hash Functions

### Recommended Hash Functions

The following hash functions have no known weaknesses, and are suitable for new applications. The SHA2 family of hash functions were specified by NIST, intended as a replacement for SHA1.

#### SHA-256

SHA256 is a member of the SHA2 family. It outputs hash values of 256 bits, or 32 octets.

```lua
local hash = require "resty.nettle.sha2"
local dgst = hash('sha256', 'test')
-- or
local dgst = hash.sha256('test')
-- or
local s256 = hash.sha256.new()
s256:update('te')
s256:update('et')
local dgst = s256:digest()
```

#### SHA-224

SHA224 is a variant of SHA256, with a different initial state, and with the output truncated to 224 bits, or 28 octets.

```lua
local hash = require "resty.nettle.sha2"
local dgst = hash('sha224', 'test')
-- or
local dgst = hash.sha224('test')
-- or
local s224 = hash.sha224..new()
s224:update('te')
s224:update('et')
local dgst = s224:digest()
```

#### SHA-512

SHA512 is a larger sibling to SHA256, with a very similar structure but with both the output and the internal variables of twice the size. The internal variables are 64 bits rather than 32, making it significantly slower on 32-bit computers. It outputs hash values of 512 bits, or 64 octets.

```lua
local hash = require "resty.nettle.sha2"
local dgst = hash('sha512', 'test')
-- or
local dgst = hash.sha512('test')
-- or
local s512 = hash.sha512.new()
s512:update('te')
s512:update('et')
local dgst = s512:digest()
```

#### SHA-384, SHA-512/224,  and SHA-512/256

Several variants of SHA512 have been defined, with a different initial state, and with the output truncated to shorter length than 512 bits. Naming is a bit confused, these algorithms are call SHA-512/224, SHA-512/256 and SHA384, for output sizes of 224, 256 and 384 bits, respectively. 

#### SHA-384

```lua
local hash = require "resty.nettle.sha2"
local dgst = hash('sha384', 'test')
-- or
local dgst = hash.sha384('test')
-- or
local s384 = hash.sha384.new()
s512:update('te')
s512:update('et')
local dgst = s384:digest()
```

#### SHA-512/224

```lua
local hash = require "resty.nettle.sha2"
local dgst = hash('sha512_224', 'test')
-- or
local dgst = hash.sha512_224('test')
-- or
local s512_224 = hash.sha512_224.new()
s512_224:update('te')
s512_224:update('et')
local dgst = s512_224:digest()
```

#### SHA-512/256

```lua
local hash = require "resty.nettle.sha2"
local dgst = hash('sha512_256', 'test')
-- or
local dgst = hash.sha512_265('test')
-- or
local s512_256 = hash.sha512_256.new()
s512_256:update('te')
s512_256:update('et')
local dgst = s512_256:digest()
```

#### SHA3-224

The SHA3 hash functions were specified by NIST in response to weaknesses in SHA1, and doubts about SHA2 hash functions which structurally are very similar to SHA1. SHA3 is a result of a competition, where the winner, also known as Keccak, was designed by Guido Bertoni, Joan Daemen, Michaël Peeters and Gilles Van Assche. It is structurally very different from all widely used earlier hash functions. Like SHA2, there are several variants, with output sizes of 224, 256, 384 and 512 bits (28, 32, 48 and 64 octets, respectively).

Nettle's implementation of SHA3 should be considered experimental. It is based on the design from the competition. Unfortunately, it is likely that when the standard is finalized, there will be small changes making Nettle's current implementation incompatible with the standard. Nettle's implementation may need incompatible changes to track standardization. Latest standard draft, at the time of writing, is at http://csrc.nist.gov/publications/drafts/fips-202/fips_202_draft.pdf.

```lua
local hash = require "resty.nettle.sha3"
local dgst = hash(224, 'test')
-- or
local dgst = hash.sha224('test')
-- or
local s224 = hash.sha224.new()
s224:update('te')
s224:update('et')
local dgst = s224:digest()
```

#### SHA3-256

This is SHA3 with 256-bit output size, and possibly the most useful of the SHA3 hash functions.

```lua
local hash = require "resty.nettle.sha3"
local dgst = hash(256, 'test')
-- or
local dgst = hash.sha256('test')
-- or
local s256 = hash.sha256.new()
s256:update('te')
s256:update('et')
local dgst = s256:digest()
```

#### SHA3-384

This is SHA3 with 384-bit output size.

```lua
local hash = require "resty.nettle.sha3"
local dgst = hash(384, 'test')
-- or
local dgst = hash.sha384('test')
-- or
local s384 = hash.sha384.new()
s384:update('te')
s384:update('et')
local dgst = s384:digest()
```

#### SHA3-512

This is SHA3 with 512-bit output size.

```lua
local hash = require "resty.nettle.sha3"
local dgst = hash(512, 'test')
-- or
local dgst = hash.sha512('test')
-- or
local s512 = hash.sha512.new()
s512:update('te')
s512:update('et')
local dgst = s512:digest()
```

### Legacy Hash Functions

The hash functions in this section all have some known weaknesses, and should be avoided for new applications. These hash functions are mainly useful for compatibility with old applications and protocols. Some are still considered safe as building blocks for particular constructions, e.g., there seems to be no known attacks against HMAC-SHA1 or even HMAC-MD5. In some important cases, use of a “legacy” hash function does not in itself make the application insecure; if a known weakness is relevant depends on how the hash function is used, and on the threat model.

#### MD5

MD5 is a message digest function constructed by Ronald Rivest, and described in RFC 1321. It outputs message digests of 128 bits, or 16 octets.

#### MD2

MD2 is another hash function of Ronald Rivest's, described in RFC 1319. It outputs message digests of 128 bits, or 16 octets.

#### MD4

MD4 is a predecessor of MD5, described in RFC 1320. Like MD5, it is constructed by Ronald Rivest. It outputs message digests of 128 bits, or 16 octets. Use of MD4 is not recommended, but it is sometimes needed for compatibility with existing applications and protocols.

#### RIPEMD160

RIPEMD160 is a hash function designed by Hans Dobbertin, Antoon Bosselaers, and Bart Preneel, as a strengthened version of RIPEMD (which, like MD4 and MD5, fails the collision-resistance requirement). It produces message digests of 160 bits, or 20 octets.

#### SHA-1

SHA1 is a hash function specified by NIST (The U.S. National Institute for Standards and Technology). It outputs hash values of 160 bits, or 20 octets.

#### GOSTHASH94

The GOST94 or GOST R 34.11-94 hash algorithm is a Soviet-era algorithm used in Russian government standards (see RFC 4357). It outputs message digests of 256 bits, or 32 octets.

## Cipher Functions

A cipher is a function that takes a message or plaintext and a secret key and transforms it to a ciphertext. Given only the ciphertext, but not the key, it should be hard to find the plaintext. Given matching pairs of plaintext and ciphertext, it should be hard to find the key.

#### AES

AES is a block cipher, specified by NIST as a replacement for the older DES standard. The standard is the result of a competition between cipher designers. The winning design, also known as RIJNDAEL, was constructed by Joan Daemen and Vincent Rijnmen.

Like all the AES candidates, the winning design uses a block size of 128 bits, or 16 octets, and three possible key-size, 128, 192 and 256 bits (16, 24 and 32 octets) being the allowed key sizes. It does not have any weak keys.

#### ARCFOUR

ARCFOUR is a stream cipher, also known under the trade marked name RC4, and it is one of the fastest ciphers around. A problem is that the key setup of ARCFOUR is quite weak, you should never use keys with structure, keys that are ordinary passwords, or sequences of keys like “secret:1”, “secret:2”... If you have keys that don't look like random bit strings, and you want to use ARCFOUR, always hash the key before feeding it to ARCFOUR. Furthermore, the initial bytes of the generated key stream leak information about the key; for this reason, it is recommended to discard the first 512 bytes of the key stream.

#### ARCTWO

ARCTWO (also known as the trade marked name RC2) is a block cipher specified in RFC 2268. Nettle also include a variation of the ARCTWO set key operation that lack one step, to be compatible with the reverse engineered RC2 cipher description, as described in a Usenet post to sci.crypt by Peter Gutmann.

ARCTWO uses a block size of 64 bits, and variable key-size ranging from 1 to 128 octets. Besides the key, ARCTWO also has a second parameter to key setup, the number of effective key bits, ekb. This parameter can be used to artificially reduce the key size. In practice, ekb is usually set equal to the input key size.

We do not recommend the use of ARCTWO; the Nettle implementation is provided primarily for interoperability with existing applications and standards.

#### BLOWFISH

BLOWFISH is a block cipher designed by Bruce Schneier. It uses a block size of 64 bits (8 octets), and a variable key size, up to 448 bits. It has some weak keys.

#### Camellia

Camellia is a block cipher developed by Mitsubishi and Nippon Telegraph and Telephone Corporation, described in RFC3713. It is recommended by some Japanese and European authorities as an alternative to AES, and it is one of the selected algorithms in the New European Schemes for Signatures, Integrity and Encryption (NESSIE) project. The algorithm is patented. The implementation in Nettle is derived from the implementation released by NTT under the GNU LGPL (v2.1 or later), and relies on the implicit patent license of the LGPL. There is also a statement of royalty-free licensing for Camellia at http://www.ntt.co.jp/news/news01e/0104/010417.html, but this statement has some limitations which seem problematic for free software.

Camellia uses a the same block size and key sizes as AES: The block size is 128 bits (16 octets), and the supported key sizes are 128, 192, and 256 bits. The variants with 192 and 256 bit keys are identical, except for the key setup.

#### CAST128

CAST-128 is a block cipher, specified in RFC 2144. It uses a 64 bit (8 octets) block size, and a variable key size of up to 128 bits.

#### ChaCha

ChaCha is a variant of the stream cipher Salsa20, also designed by D. J. Bernstein. For more information on Salsa20, see below.

#### DES

DES is the old Data Encryption Standard, specified by NIST. It uses a block size of 64 bits (8 octets), and a key size of 56 bits. However, the key bits are distributed over 8 octets, where the least significant bit of each octet may be used for parity. A common way to use DES is to generate 8 random octets in some way, then set the least significant bit of each octet to get odd parity, and initialize DES with the resulting key.

The key size of DES is so small that keys can be found by brute force, using specialized hardware or lots of ordinary work stations in parallel. One shouldn't be using plain DES at all today, if one uses DES at all one should be using "triple DES", see DES3 below.

#### DES3

The inadequate key size of DES has already been mentioned. One way to increase the key size is to pipe together several DES boxes with independent keys. It turns out that using two DES ciphers is not as secure as one might think, even if the key size of the combination is a respectable 112 bits.

The standard way to increase DES's key size is to use three DES boxes. The mode of operation is a little peculiar: the middle DES box is wired in the reverse direction. To encrypt a block with DES3, you encrypt it using the first 56 bits of the key, then decrypt it using the middle 56 bits of the key, and finally encrypt it again using the last 56 bits of the key. This is known as “ede” triple-DES, for “encrypt-decrypt-encrypt”.

The “ede” construction provides some backward compatibility, as you get plain single DES simply by feeding the same key to all three boxes. That should help keeping down the gate count, and the price, of hardware circuits implementing both plain DES and DES3.

DES3 has a key size of 168 bits, but just like plain DES, useless parity bits are inserted, so that keys are represented as 24 octets (192 bits). As a 112 bit key is large enough to make brute force attacks impractical, some applications uses a “two-key” variant of triple-DES. In this mode, the same key bits are used for the first and the last DES box in the pipe, while the middle box is keyed independently. The two-key variant is believed to be secure, i.e. there are no known attacks significantly better than brute force.

Naturally, it's simple to implement triple-DES on top of Nettle's DES functions.

#### Salsa20

Salsa20 is a fairly recent stream cipher designed by D. J. Bernstein. It is built on the observation that a cryptographic hash function can be used for encryption: Form the hash input from the secret key and a counter, xor the hash output and the first block of the plaintext, then increment the counter to process the next block (similar to CTR mode, see see CTR). Bernstein defined an encryption algorithm, Snuffle, in this way to ridicule United States export restrictions which treated hash functions as nice and harmless, but ciphers as dangerous munitions.

Salsa20 uses the same idea, but with a new specialized hash function to mix key, block counter, and a couple of constants. It's also designed for speed; on x86_64, it is currently the fastest cipher offered by nettle. It uses a block size of 512 bits (64 octets) and there are two specified key sizes, 128 and 256 bits (16 and 32 octets).

Caution: The hash function used in Salsa20 is not directly applicable for use as a general hash function. It's not collision resistant if arbitrary inputs are allowed, and furthermore, the input and output is of fixed size.

When using Salsa20 to process a message, one specifies both a key and a nonce, the latter playing a similar role to the initialization vector (IV) used with CBC or CTR mode. One can use the same key for several messages, provided one uses a unique random iv for each message. The iv is 64 bits (8 octets). The block counter is initialized to zero for each message, and is also 64 bits (8 octets).

#### SERPENT

SERPENT is one of the AES finalists, designed by Ross Anderson, Eli Biham and Lars Knudsen. Thus, the interface and properties are similar to AES'. One peculiarity is that it is quite pointless to use it with anything but the maximum key size, smaller keys are just padded to larger ones.

#### TWOFISH

Another AES finalist, this one designed by Bruce Schneier and others.

## Cipher Modes

#### Cipher Block Chaining (CBC)
#### Counter Mode (CTR)

## Authenticated Encryption with Associated Data

#### EAX
#### Galois Counter Mode (GCM)
#### Counter with CBC-MAC Mode (CCM)
#### ChaCha-Poly1305

## Keyed Hash Functions

#### HMAC

##### HMAC-MD5
##### HMAC-RIPEMD160
##### HMAC-SHA1
##### HMAC-SHA256
##### HMAC-SHA512

#### UMAC
#### Poly1305

## Key Derivation Functions

#### PBKDF2

##### PBKDF2-HMAC-SHA1
##### PBKDF2-HMAC-SHA256


## Randomness

#### Yarrow

## ASCII Encoding

#### Base64
#### Base16

## License

`lua-resty-nettle` uses two clause BSD license.

```
Copyright (c) 2014, Aapo Talvensaari
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice, this
  list of conditions and the following disclaimer in the documentation and/or
  other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```
