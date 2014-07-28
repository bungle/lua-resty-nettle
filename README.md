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

### SHA-512

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

### SHA-384, SHA-512/224,  and SHA-512/256

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

### SHA3-224

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

### SHA3-256

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

### SHA3-384

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

### SHA3-512

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
