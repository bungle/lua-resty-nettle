# lua-resty-nettle

LuaJIT FFI bindings for [Nettle](http://www.lysator.liu.se/~nisse/nettle/nettle.html) (a low-level cryptographic library)

## Status

All the bindings that do not depend on [GMP](https://gmplib.org/) are ready to use. The [GMP](https://gmplib.org/) depended functionality is the [public-key algorithms](http://www.lysator.liu.se/~nisse/nettle/nettle.html#Public_002dkey-algorithms) (i.e. RSA, DSA, and ECDSA), and ONLY the RSA functions have some support right now, although the APIs might change. Much of the documentation here is copied from [Nettle's documentation](http://www.lysator.liu.se/~nisse/nettle/nettle.html), but I have included Lua examples to it. I will be adding more documentation shortly.

## Synopsis

```lua
local function hex(str, spacer)
    return (string.gsub(str, "(.)", function (c)
        return string.format("%02X%s", string.byte(c), spacer or "")
    end))
end

do
    local md2 = require "resty.nettle.md2"
    print("md2      ", #md2(""), hex(md2("")))
    local hash = md2.new()
    hash:update("")
    print("md2     ", #hash:digest(), hex(hash:digest()))
end

do
    local md4 = require "resty.nettle.md4"
    print("md4      ", #md4(""), hex(md4("")))
    local hash = md4.new()
    hash:update("")
    print("md4      ", #hash:digest(), hex(hash:digest()))
end

do
    local md5 = require "resty.nettle.md5"
    print("md5      ", #md5(""), hex(md5("")))
    local hash = md5.new()
    hash:update("")
    print("md5      ", #hash:digest(), hex(hash:digest()))
end

do
    local ripemd160 = require "resty.nettle.ripemd160"
    local hash = ripemd160.new()
    hash:update("")
    print("ripemd160", #hash:digest(), hex(hash:digest()))
end

do
    local gosthash94 = require "resty.nettle.gosthash94"
    local hash = gosthash94.new()
    hash:update("")
    print("gosthash94", #hash:digest(), hex(hash:digest()))
end

do
    local sha1 = require "resty.nettle.sha1"
    print("sha1      ", #sha1(""), hex(sha1("")))
    local hash = sha1.new()
    hash:update("")
    print("sha1     ", #hash:digest(), hex(hash:digest()))
end

do
    local sha1 = require "resty.nettle.sha1"
    print("sha1      ", #sha1(""), hex(sha1("")))
    local hash = sha1.new()
    hash:update("")
    print("sha1     ", #hash:digest(), hex(hash:digest()))
end

do
    local sha2 = require "resty.nettle.sha2"

    local hash = sha2.sha224.new()
    hash:update("")
    print("sha224      ", #hash:digest(), hex(hash:digest()))
    print("sha224      ", #sha2.sha224(""), hex(sha2.sha224("")))

    local hash = sha2.sha256.new()
    hash:update("")
    print("sha256      ", #hash:digest(), hex(hash:digest()))
    print("sha256      ", #sha2.sha256(""), hex(sha2.sha256("")))

    local hash = sha2.sha384.new()
    hash:update("")
    print("sha384      ", #hash:digest(), hex(hash:digest()))
    print("sha384      ", #sha2.sha384(""), hex(sha2.sha384("")))

    local hash = sha2.sha512.new()
    hash:update("")
    print("sha512      ", #hash:digest(), hex(hash:digest()))
    print("sha512      ", #sha2.sha512(""), hex(sha2.sha512("")))

    local hash = sha2.sha512_224.new()
    hash:update("")
    print("sha512_224", #hash:digest(), hex(hash:digest()))
    print("sha512_224", #sha2.sha512_224(""), hex(sha2.sha512_224("")))

    local hash = sha2.sha512_256.new()
    hash:update("")
    print("sha512_256", #hash:digest(), hex(hash:digest()))
    print("sha512_256", #sha2.sha512_256(""), hex(sha2.sha512_256("")))
end

do
    local sha3 = require "resty.nettle.sha3"

    local hash = sha3.sha224.new()
    hash:update("")
    print("sha3 224", #hash:digest(), hex(hash:digest()))

    local hash = sha3.sha256.new()
    hash:update("")
    print("sha3 256", #hash:digest(), hex(hash:digest()))

    local hash = sha3.sha384.new()
    hash:update("")
    print("sha3 384", #hash:digest(), hex(hash:digest()))

    local hash = sha3.sha512.new()
    hash:update("")
    print("sha3 512", #hash:digest(), hex(hash:digest()))
end

do
    local hmac = require "resty.nettle.hmac"
    print("hmac md5", #hmac("md5", "a", "a"), hex(hmac("md5", "a", "a")))
    print("hmac md5", #hmac.md5("a", "a"), hex(hmac.md5("a", "a")))
    local hash = hmac.md5.new("a")
    hash:update("a")
    local dgst = hash:digest()
    print("hmac md5", #dgst, hex(dgst))

    local hash = hmac.ripemd160.new("a")
    hash:update("a")
    local dgst = hash:digest()
    print("hmac ripemd160", #dgst, hex(dgst))

    local hash = hmac.sha1.new("a")
    hash:update("a")
    local dgst = hash:digest()
    print("hmac sha1", #dgst, hex(dgst))

    local hash = hmac.sha224.new("a")
    hash:update("a")
    local dgst = hash:digest()
    print("hmac sha224", #dgst, hex(dgst))

    local hash = hmac.sha256.new("a")
    hash:update("a")
    local dgst = hash:digest()
    print("hmac sha256", #dgst, hex(dgst))
  
    local hash = hmac.sha384.new("a")
    hash:update("a")
    local dgst = hash:digest()
    print("hmac sha384", #dgst, hex(dgst))

    local hash = hmac.sha512.new("a")
    hash:update("a")
    local dgst = hash:digest()
    print("hmac sha512", #dgst, hex(dgst))
end

do
    local umac = require "resty.nettle.umac"
    local hash = umac.umac32.new("umac32")
    hash:update("")
    local dgst = hash:digest()
    print("umac32     ", #dgst, hex(dgst))

    local hash = umac.umac64.new("umac64")
    hash:update("")
    local dgst = hash:digest()
    print("umac64     ", #dgst, hex(dgst))

    local hash = umac.umac96.new("umac96")
    hash:update("")
    local dgst = hash:digest()
    print("umac96     ", #dgst, hex(dgst))

    local hash = umac.umac128.new("umac128")
    hash:update("")
    local dgst = hash:digest()
    print("umac128     ", #dgst, hex(dgst))
end

do
    local poly = require "resty.nettle.poly1305"
    local hash = poly.new("poly")
    hash:update("")
    local dgst = hash:digest()
    print("poly1305    ", #dgst, hex(dgst))
end

do
    local pbkdf2 = require "resty.nettle.pbkdf2"
    local hmac = pbkdf2.hmac_sha1("password", 1, "salt", 20)
    print("pbkdf2 sha1", #hmac, hex(hmac))
    local hmac = pbkdf2.hmac_sha256("pass\0word", 4096, "sa\0lt", 32)
    print("pbkdf2 sha256", #hmac, hex(hmac))
end

print()

do
    local aes = require "resty.nettle.aes"
    local aes128 = aes.new("testtesttesttest")
    local ciphertext = aes128:encrypt("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    print("aes128 encrypt", #ciphertext, hex(ciphertext))
    local aes128 = aes.new("testtesttesttest")
    local plaintext = aes128:decrypt(ciphertext)
    print("aes128 decrypt", #plaintext, plaintext)

    print()

    local aes128 = aes.new("testtesttesttest", "cbc", "testtesttesttest")
    local ciphertext = aes128:encrypt("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    print("aes128 cbc enc", #ciphertext, hex(ciphertext))
    local aes128 = aes.new("testtesttesttest", "cbc", "testtesttesttest")
    local plaintext = aes128:decrypt(ciphertext)
    print("aes128 cbc dec", #plaintext, plaintext)

    print()

    local aes128 = aes.new("testtesttesttest", "ctr", "testtesttesttest")
    local ciphertext = aes128:encrypt("a")
    print("aes128 ctr enc", #ciphertext, hex(ciphertext))
    local aes128 = aes.new("testtesttesttest", "ctr", "testtesttesttest")
    local plaintext = aes128:decrypt(ciphertext)
    print("aes128 ctr dec", #plaintext, plaintext)

    print()

    local aes128 = aes.new("testtesttesttest", "eax", "testtesttest")
    local ciphertext, digest = aes128:encrypt("a")
    print("aes128 eax enc", #ciphertext, hex(ciphertext))
    print("aes128 eax dgst", #digest, hex(digest))
    local aes128 = aes.new("testtesttesttest", "eax", "testtesttest")
    local plaintext, digest = aes128:decrypt(ciphertext)
    print("aes128 eax dec", #plaintext, plaintext)
    print("aes128 eax dgst", #digest, hex(digest))

    print()

    local aes128 = aes.new("testtesttesttest", "gcm", "testtesttest")
    local ciphertext, digest = aes128:encrypt("a")
    print("aes128 gcm enc", #ciphertext, hex(ciphertext))
    print("aes128 gcm dgst", #digest, hex(digest))
    local aes128 = aes.new("testtesttesttest", "gcm", "testtesttest")
    local plaintext, digest = aes128:decrypt(ciphertext)
    print("aes128 gcm dec", #plaintext, plaintext)
    print("aes128 gcm dgst", #digest, hex(digest))

    print()

    local aes128 = aes.new("testtesttesttest", "ccm", "testtesttest")
    local ciphertext, digest = aes128:encrypt("a")
    print("aes128 ccm enc", #ciphertext, hex(ciphertext))
    print("aes128 ccm dgst", #digest, hex(digest))
    local aes128 = aes.new("testtesttesttest", "ccm", "testtesttest")
    local plaintext, digest = aes128:decrypt(ciphertext)
    print("aes128 ccm dec", #plaintext, plaintext)
    print("aes128 ccm dgst", #digest, hex(digest))

    print()

    local aes192 = aes.new("testtesttesttesttesttest")
    local ciphertext = aes192:encrypt("a")
    print("aes192 encrypt", #ciphertext, hex(ciphertext))
    local aes192 = aes.new("testtesttesttesttesttest")
    local plaintext = aes192:decrypt(ciphertext)
    print("aes192 decrypt", #plaintext, plaintext)
    
    print()

    local aes192 = aes.new("testtesttesttesttesttest", "cbc", "testtesttesttest")
    local ciphertext = aes192:encrypt("a")
    print("aes192 cbc enc", #ciphertext, hex(ciphertext))
    local aes192 = aes.new("testtesttesttesttesttest", "cbc", "testtesttesttest")
    local plaintext = aes192:decrypt(ciphertext)
    print("aes192 cbc dec", #plaintext, plaintext)

    print()

    local aes192 = aes.new("testtesttesttesttesttest", "ctr", "testtesttesttest")
    local ciphertext = aes192:encrypt("a")
    print("aes192 ctr enc", #ciphertext, hex(ciphertext))
    local aes192 = aes.new("testtesttesttesttesttest", "ctr", "testtesttesttest")
    local plaintext = aes192:decrypt(ciphertext)
    print("aes192 ctr dec", #plaintext, plaintext)

    print()

    local aes192 = aes.new("testtesttesttesttesttest", "gcm", "testtesttest")
    local ciphertext, digest = aes192:encrypt("a")
    print("aes192 gcm enc", #ciphertext, hex(ciphertext))
    print("aes192 gcm dgst", #digest, hex(digest))
    local aes192 = aes.new("testtesttesttesttesttest", "gcm", "testtesttest")
    local plaintext, digest = aes192:decrypt(ciphertext)
    print("aes192 gcm dec", #plaintext, plaintext)
    print("aes192 gcm dgst", #digest, hex(digest))

    print()

    local aes192 = aes.new("testtesttesttesttesttest", "ccm", "testtesttest")
    local ciphertext, digest = aes192:encrypt("a")
    print("aes192 ccm enc", #ciphertext, hex(ciphertext))
    print("aes192 ccm dgst", #digest, hex(digest))
    local aes192 = aes.new("testtesttesttesttesttest", "ccm", "testtesttest")
    local plaintext, digest = aes192:decrypt(ciphertext)
    print("aes192 ccm dec", #plaintext, plaintext)
    print("aes192 ccm dgst", #digest, hex(digest))

    print()
    
    local aes256 = aes.new("testtesttesttesttesttesttesttest")
    local ciphertext = aes256:encrypt("a")
    print("aes256 encrypt", #ciphertext, hex(ciphertext))
    local aes256 = aes.new("testtesttesttesttesttesttesttest")
    local plaintext = aes256:decrypt(ciphertext)
    print("aes256 decrypt", #plaintext, plaintext)

    print()

    local aes256 = aes.new("testtesttesttesttesttesttesttest", "cbc", "testtesttesttest")
    local ciphertext = aes256:encrypt("a")
    print("aes256 cbc enc", #ciphertext, hex(ciphertext))
    local aes256 = aes.new("testtesttesttesttesttesttesttest", "cbc", "testtesttesttest")
    local plaintext = aes256:decrypt(ciphertext)
    print("aes256 cbc dec", #plaintext, plaintext)

    print()

    local aes256 = aes.new("testtesttesttesttesttesttesttest", "ctr", "testtesttesttest")
    local ciphertext = aes256:encrypt("a")
    print("aes256 ctr enc", #ciphertext, hex(ciphertext))
    local aes256 = aes.new("testtesttesttesttesttesttesttest", "ctr", "testtesttesttest")
    local plaintext = aes256:decrypt(ciphertext)
    print("aes256 ctr dec", #plaintext, plaintext)

    print()

    local aes256 = aes.new("testtesttesttesttesttesttesttest", "gcm", "testtesttest", "testtesttesttest1asdasdasdasdasdasdasdasdasdasdasdasdasdasdasd")
    local ciphertext, digest = aes256:encrypt("a")
    print("aes256 gcm enc", #ciphertext, hex(ciphertext))
    print("aes256 gcm dgst", #digest, hex(digest))
    local aes256 = aes.new("testtesttesttesttesttesttesttest", "gcm", "testtesttest", "testtesttesttest1asdasdasdasdasdasdasdasdasdasdasdasdasdasdasd")
    local plaintext, digest = aes256:decrypt(ciphertext)
    print("aes256 gcm dec", #plaintext, plaintext)
    print("aes256 gcm dgst", #digest, hex(digest))

    print()

    local aes256 = aes.new("testtesttesttesttesttesttesttest", "ccm", "testtesttest", "testtesttesttest1asdasdasdasdasdasdasdasdasdasdasdasdasdasdasd")
    local ciphertext, digest = aes256:encrypt("a")
    print("aes256 ccm enc", #ciphertext, hex(ciphertext))
    print("aes256 ccm dgst", #digest, hex(digest))
    local aes256 = aes.new("testtesttesttesttesttesttesttest", "ccm", "testtesttest", "testtesttesttest1asdasdasdasdasdasdasdasdasdasdasdasdasdasdasd")
    local plaintext, digest = aes256:decrypt(ciphertext)
    print("aes256 ccm dec", #plaintext, plaintext)
    print("aes256 ccm dgst", #digest, hex(digest))
end

print()

do
    local camellia = require "resty.nettle.camellia"
    local camellia128 = camellia.new("testtesttesttest")
    local ciphertext = camellia128:encrypt("a")
    print("cam128 encrypt", #ciphertext, hex(ciphertext))
    local camellia128 = camellia.new("testtesttesttest")
    local plaintext = camellia128:decrypt(ciphertext)
    print("cam128 decrypt", #plaintext, plaintext)

    print()

    local camellia128 = camellia.new("testtesttesttest", "gcm", "testtesttest")
    local ciphertext, digest = camellia128:encrypt("a")
    print("cam128 gcm enc", #ciphertext, hex(ciphertext))
    print("cam128 gcm dgst", #digest, hex(digest))
    local camellia128 = camellia.new("testtesttesttest", "gcm", "testtesttest")
    local plaintext, digest = camellia128:decrypt(ciphertext)
    print("cam128 gcm dec", #plaintext, plaintext)
    print("cam128 gcm dgst", #digest, hex(digest))

    print()

    local camellia192 = camellia.new("testtesttesttesttesttest")
    local ciphertext = camellia192:encrypt("a")
    print("cam192 encrypt", #ciphertext, hex(ciphertext))
    local camellia192 = camellia.new("testtesttesttesttesttest")
    local plaintext = camellia192:decrypt(ciphertext)
    print("cam192 decrypt", #plaintext, plaintext)

    print()

    local camellia256 = camellia.new("testtesttesttesttesttesttesttest")
    local ciphertext = camellia256:encrypt("a")
    print("cam256 encrypt", #ciphertext, hex(ciphertext))
    local camellia256 = camellia.new("testtesttesttesttesttesttesttest")
    local plaintext = camellia256:decrypt(ciphertext)
    print("cam256 decrypt", #plaintext, plaintext)

    print()

    local camellia256 = camellia.new("testtesttesttesttesttesttesttest", "gcm", "testtesttest", "testtesttesttest1asdasdasdasdasdasdasdasdasdasdasdasdasdasdasd")
    local ciphertext, digest = camellia256:encrypt("a")
    print("cam256 gcm enc", #ciphertext, hex(ciphertext))
    print("cam256 gcm dgst", #digest, hex(digest))
    local camellia256 = camellia.new("testtesttesttesttesttesttesttest", "gcm", "testtesttest", "testtesttesttest1asdasdasdasdasdasdasdasdasdasdasdasdasdasdasd")
    local plaintext, digest = camellia256:decrypt(ciphertext)
    print("cam256 gcm dec", #plaintext, plaintext)
    print("cam256 gcm dgst", #digest, hex(digest))
end

print()

do
    local arcfour = require "resty.nettle.arcfour"
    local af = arcfour.new("testtesttesttest")
    local ciphertext = af:encrypt("a")
    print("ARCFOUR encrypt", #ciphertext, hex(ciphertext))
    local af = arcfour.new("testtesttesttest")
    local plaintext = af:decrypt(ciphertext)
    print("ARCFOUR decrypt", #plaintext, plaintext)
end

print()

do
    local blowfish = require "resty.nettle.blowfish"
    local bf = blowfish.new("testtesttesttest")
    local ciphertext = bf:encrypt("a")
    print("BLOWFISH enc", #ciphertext, hex(ciphertext))
    local bf = blowfish.new("testtesttesttest")
    local plaintext = bf:decrypt(ciphertext)
    print("BLOWFISH dec", #plaintext, plaintext)
end

print()

do
    local twofish = require "resty.nettle.twofish"
    local tf = twofish.new("testtesttesttest")
    local ciphertext = tf:encrypt("a")
    print("TWOFISH enc", #ciphertext, hex(ciphertext))
    local tf = twofish.new("testtesttesttest")
    local plaintext = tf:decrypt(ciphertext)
    print("TWOFISH dec", #plaintext, plaintext)
end

print()

do
    local serpent = require "resty.nettle.serpent"
    local sp = serpent.new("testtesttesttest")
    local ciphertext = sp:encrypt("a")
    print("SERPENT enc", #ciphertext, hex(ciphertext))
    local sp = serpent.new("testtesttesttest")
    local plaintext = sp:decrypt(ciphertext)
    print("SERPENT dec", #plaintext, plaintext)
end

print()

do
    local cast128 = require "resty.nettle.cast128"
    local ct = cast128.new("testtesttesttest")
    local ciphertext = ct:encrypt("a")
    print("CAST128 enc", #ciphertext, hex(ciphertext))
    local ct = cast128.new("testtesttesttest")
    local plaintext = ct:decrypt(ciphertext)
    print("CAST128 dec", #plaintext, plaintext)
end

print()

do
    local chacha = require "resty.nettle.chacha"
    local cc = chacha.new("testtesttesttesttesttesttesttest", "testtest")
    local ciphertext = cc:encrypt("a")
    print("ChaCha enc", #ciphertext, hex(ciphertext))
    local cc = chacha.new("testtesttesttesttesttesttesttest", "testtest")
    local plaintext = cc:decrypt(ciphertext)
    print("ChaCha dec", #plaintext, plaintext)
end

print()

do
    local salsa20 = require "resty.nettle.salsa20"
    local ss = salsa20.new("testtesttesttest", "testtest")
    local ciphertext = ss:encrypt("a")
    print("Salsa20 128 enc", #ciphertext, hex(ciphertext))
    local ss = salsa20.new("testtesttesttest", "testtest")
    local plaintext = ss:decrypt(ciphertext)
    print("Salsa20 128 dec", #plaintext, plaintext)
end

print()

do
    local salsa20 = require "resty.nettle.salsa20"
    local ss = salsa20.new("testtesttesttesttesttesttesttest", "testtest")
    local ciphertext = ss:encrypt("a")
    print("Salsa20 256 enc", #ciphertext, hex(ciphertext))
    local ss = salsa20.new("testtesttesttesttesttesttesttest", "testtest")
    local plaintext = ss:decrypt(ciphertext)
    print("Salsa20 256 dec", #plaintext, plaintext)
end

print()

do
    local salsa20 = require "resty.nettle.salsa20"
    local ss = salsa20.new("testtesttesttest", "testtest", 12)
    local ciphertext = ss:encrypt("a")
    print("Sal20r12 128 e", #ciphertext, hex(ciphertext))
    local ss = salsa20.new("testtesttesttest", "testtest", 12)
    local plaintext = ss:decrypt(ciphertext)
    print("Sal20r12 128 d", #plaintext, plaintext)
end

print()

do
    local salsa20 = require "resty.nettle.salsa20"
    local ss = salsa20.new("testtesttesttesttesttesttesttest", "testtest", 12)
    local ciphertext = ss:encrypt("a")
    print("Sal20r12 256 e", #ciphertext, hex(ciphertext))
    local ss = salsa20.new("testtesttesttesttesttesttesttest", "testtest", 12)
    local plaintext = ss:decrypt(ciphertext)
    print("Sal20r12 256 d", #plaintext, plaintext)
end

print()

do
    local chacha_poly1305 = require "resty.nettle.chacha-poly1305"
    local cp = chacha_poly1305.new("testtesttesttesttesttesttesttest", "testtesttesttest", "testtest")
    local ciphertext, digest = cp:encrypt("a")
    print("cc-p1305 enc", #ciphertext, hex(ciphertext))
    print("cc-p1305 dgst", #digest, hex(digest))
    local cp = chacha_poly1305.new("testtesttesttesttesttesttesttest", "testtesttesttest", "testtest")
    local plaintext, digest = cp:decrypt(ciphertext)
    print("cc-p1305 dec", #plaintext, plaintext)
    print("cc-p1305 dgst", #digest, hex(digest))
end

print()

do
    local des = require "resty.nettle.des"
    print("DES check   ", "testtest", des.check_parity("testtest"))
    print("DES fix     ", "testtest", des.fix_parity("testtest"))
    print("DES check   ", des.fix_parity("testtest"), des.check_parity(des.fix_parity("testtest")))
end

print()

do
    local des = require "resty.nettle.des"
    local ds, wk = des.new("testtest")
    local ciphertext = ds:encrypt("a")
    print("DES enc     ", wk, #ciphertext, hex(ciphertext))
    local ds, wk = des.new("testtest")
    local plaintext = ds:decrypt(ciphertext)
    print("DES dec     ", wk, #plaintext, plaintext)
end

print()

do
    local des = require "resty.nettle.des"
    local ds, wk = des.new("testtest", "cbc", "kalakala")
    local ciphertext = ds:encrypt("testtestkalakala")
    print("DES cbc enc ", wk, #ciphertext, hex(ciphertext))
    local ds, wk = des.new("testtest", "cbc", "kalakala")
    local plaintext = ds:decrypt(ciphertext)
    print("DES cbc dec ", wk, #plaintext, plaintext)
end

print()

do
    local des = require "resty.nettle.des"
    local ds, wk = des.new("testtest", "ctr", "kalakala")
    local ciphertext = ds:encrypt("testtestkalakala")
    print("DES ctr enc ", wk, #ciphertext, hex(ciphertext))
    local ds, wk = des.new("testtest", "ctr", "kalakala")
    local plaintext = ds:decrypt(ciphertext)
    print("DES ctr dec ", wk, #plaintext, plaintext)
end

print()

do
    local des = require "resty.nettle.des"
    print("DES3 check   ", "testtestkalakalatesttest", des.check_parity("testtestkalakalatesttest"))
    print("DES3 fix     ", "testtestkalakalatesttest", des.fix_parity("testtestkalakalatesttest"))
    print("DES3 check   ", des.fix_parity("testtestkalakalatesttest"), des.check_parity(des.fix_parity("testtestkalakalatesttest")))
end

print()

do
    local des = require "resty.nettle.des"
    local ds, wk = des.new("testtestkalakalatesttest")
    local ciphertext = ds:encrypt("a")
    print("DES3 enc     ", wk, #ciphertext, hex(ciphertext))
    local ds, wk = des.new("testtestkalakalatesttest")
    local plaintext = ds:decrypt(ciphertext)
    print("DES3 dec     ", wk, #plaintext, plaintext)
end

print()

do
    local des = require "resty.nettle.des"
    local ds, wk = des.new("testtestkalakalatesttest", "cbc", "kalakala")
    local ciphertext = ds:encrypt("testtestkalakala")
    print("DES3 cbc enc", wk, #ciphertext, hex(ciphertext))
    local ds, wk = des.new("testtestkalakalatesttest", "cbc", "kalakala")
    local plaintext = ds:decrypt(ciphertext)
    print("DES3 cbc dec", wk, #plaintext, plaintext)
end

print()

do
    local des = require "resty.nettle.des"
    local ds, wk = des.new("testtestkalakalatesttest", "ctr", "kalakala")
    local ciphertext = ds:encrypt("testtestkalakala")
    print("DES3 ctr enc", wk, #ciphertext, hex(ciphertext))
    local ds, wk = des.new("testtestkalakalatesttest", "ctr", "kalakala")
    local plaintext = ds:decrypt(ciphertext)
    print("DES3 ctr dec", wk, #plaintext, plaintext)
end

print()

do
    local base64 = require "resty.nettle.base64"
    local encoded = base64.encode("testtesttesttest")
    print("BASE64 enc", #encoded, encoded)
    local decoded = base64.decode(encoded)
    print("BASE64 dec", #decoded, decoded)

    print()

    local encoded = base64.encode("testtesttesttest+&", true)
    print("BASE64 enc-url", #encoded, encoded)
    local decoded = base64.decode(encoded, true)
    print("BASE64 dec-url", #decoded, decoded)

    print()
    
    local base64enc = base64.encoder.new()
    print(base64enc:single("t"))
    print(base64enc:single("e"))
    print(base64enc:single("s"))
    print(base64enc:single("t"))
    print(base64enc:update("test"))
    print(base64enc:single("t"))
    print(base64enc:single("e"))
    print(base64enc:single("s"))
    print(base64enc:single("t"))
    print(base64enc:update("test"))
    print(base64enc:final())

    print()

    local base64dec = base64.decoder.new()
    print(base64dec:single("d"))
    print(base64dec:single("G"))
    print(base64dec:single("V"))
    print(base64dec:single("z"))
    print(base64dec:single("d"))
    print(base64dec:update("HRlc3"))
    print(base64dec:single("R"))
    print(base64dec:single("0"))
    print(base64dec:single("Z"))
    print(base64dec:single("X"))
    print(base64dec:single("N"))
    print(base64dec:single("0"))
    print(base64dec:update("dGVzdA=="))
    print(base64dec:final())
end

print()

do
    local base16 = require "resty.nettle.base16"
    local encoded = base16.encode("testtesttesttest")
    print("BASE16 enc", #encoded, encoded)
    local decoded = base16.decode(encoded)
    print("BASE16 dec", #decoded, decoded)

    print()

    local base16enc = base16.encoder.new()
    print(base16enc:single("t"))
    print(base16enc:single("e"))
    print(base16enc:single("s"))
    print(base16enc:single("t"))
    print(base16enc:update("test"))
    print(base16enc:single("t"))
    print(base16enc:single("e"))
    print(base16enc:single("s"))
    print(base16enc:single("t"))
    print(base16enc:update("test"))

    print()

    local base16dec = base16.decoder.new()
    print(base16dec:single("7"))
    print(base16dec:single("4"))
    print(base16dec:single("6"))
    print(base16dec:single("5"))
    print(base16dec:single("7"))
    print(base16dec:single("3"))
    print(base16dec:single("7"))
    print(base16dec:single("4"))
    print(base16dec:update("74657374"))
    print(base16dec:single("7"))
    print(base16dec:single("4"))
    print(base16dec:single("6"))
    print(base16dec:single("5"))
    print(base16dec:single("7"))
    print(base16dec:single("3"))
    print(base16dec:single("7"))
    print(base16dec:single("4"))
    print(base16dec:update("74657374"))
    print(base16dec:final())
end

print()

do
    local yarrow = require "resty.nettle.yarrow"
    local y = yarrow.new()
    print(y.sources)
    print(y.seeded)
    y:seed("testtesttesttesttesttesttesttest")
    print(y.seeded)

    print(hex(y:random(30)))
    print(hex(y:random(30)))

    y:fast_reseed()

    print(hex(y:random(30)))

    y:slow_reseed()
    print(hex(y:random(30)))
end

print()

do
    local knuth = require "resty.nettle.knuth-lfib"
    local k = knuth.new()
    print(k:number())
    print(k:number())
    print(hex(k:random(10)))
    local t = k:array(10)
    print(t)
    print(table.concat(t, '|'))
end

print()

do
    local hash = require "resty.nettle.hash"
    local hashes = hash.hashes
    for _, h in ipairs(hashes) do
        print(h.name, h.context_size, h.block_size, h.init, h.update, h.digest)
    end
end

print()

do
    local cipher = require "resty.nettle.cipher"
    local ciphers = cipher.ciphers
    for _, c in ipairs(ciphers) do
        print(c.name, c.context_size, c.block_size, c.key_size, c.set_encrypt_key, c.set_decrypt_key, c.encrypt, c.decrypt)
    end
end

print()

do
    local aead = require "resty.nettle.aead"
    local aeads = aead.aeads
    for _, a in ipairs(aeads) do
        print(a.name, a.context_size, a.block_size, a.key_size, a.nonce_size, a.set_encrypt_key, a.set_decrypt_key, a.set_nonce, a.update, a.encrypt, a.decrypt, a.digest)
    end
end
```

The above should output this:

```text
md2      	    16	8350E5A3E24C153DF2275C9F80692773
md2     	    16	8350E5A3E24C153DF2275C9F80692773
md4      	    16	31D6CFE0D16AE931B73C59D7E0C089C0
md4      	    16	31D6CFE0D16AE931B73C59D7E0C089C0
md5      	    16	D41D8CD98F00B204E9800998ECF8427E
md5      	    16	D41D8CD98F00B204E9800998ECF8427E
ripemd160	    20	9C1185A5C5E9FC54612808977EE8F548B2258D31
gosthash94	    32	CE85B99CC46752FFFEE35CAB9A7B0278ABB4C2D2055CFF685AF4912C49490F8D
sha1      	    20	DA39A3EE5E6B4B0D3255BFEF95601890AFD80709
sha1     	    20	DA39A3EE5E6B4B0D3255BFEF95601890AFD80709
sha224      	28	D14A028C2A3A2BC9476102BB288234C415A2B01F828EA62AC5B3E42F
sha224      	28	D14A028C2A3A2BC9476102BB288234C415A2B01F828EA62AC5B3E42F
sha256      	32	E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855
sha256      	32	E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855
sha384      	48	38B060A751AC96384CD9327EB1B1E36A21FDB71114BE07434C0CC7BF63F6E1DA274EDEBFE76F65FBD51AD2F14898B95B
sha384      	48	38B060A751AC96384CD9327EB1B1E36A21FDB71114BE07434C0CC7BF63F6E1DA274EDEBFE76F65FBD51AD2F14898B95B
sha512      	64	CF83E1357EEFB8BDF1542850D66D8007D620E4050B5715DC83F4A921D36CE9CE47D0D13C5D85F2B0FF8318D2877EEC2F63B931BD47417A81A538327AF927DA3E
sha512      	64	CF83E1357EEFB8BDF1542850D66D8007D620E4050B5715DC83F4A921D36CE9CE47D0D13C5D85F2B0FF8318D2877EEC2F63B931BD47417A81A538327AF927DA3E
sha512_224	    28	6ED0DD02806FA89E25DE060C19D3AC86CABB87D6A0DDD05C333B84F4
sha512_224	    28	6ED0DD02806FA89E25DE060C19D3AC86CABB87D6A0DDD05C333B84F4
sha512_256	    32	C672B8D1EF56ED28AB87C3622C5114069BDD3AD7B8F9737498D0C01ECEF0967A
sha512_256	    32	C672B8D1EF56ED28AB87C3622C5114069BDD3AD7B8F9737498D0C01ECEF0967A
sha3 224	    28	F71837502BA8E10837BDD8D365ADB85591895602FC552B48B7390ABD
sha3 256	    32	C5D2460186F7233C927E7DB2DCC703C0E500B653CA82273B7BFAD8045D85A470
sha3 384	    48	2C23146A63A29ACF99E73B88F8C24EAA7DC60AA771780CCC006AFBFA8FE2479B2DD2B21362337441AC12B515911957FF
sha3 512	    64	0EAB42DE4C3CEB9235FC91ACFFE746B29C29A8C366B7C60E4E67C466F36A4304C00FA9CAF9D87976BA469BCBE06713B435F091EF2769FB160CDAB33D3670680E
hmac md5	    16	06F30DC9049F859EA0CCB39FDC8FD5C2
hmac md5	    16	06F30DC9049F859EA0CCB39FDC8FD5C2
hmac md5	    16	06F30DC9049F859EA0CCB39FDC8FD5C2
hmac ripemd160	20	ECB2E5CA0EEFFD84F5566B5DE1D037EF1F9689EF
hmac sha1	    20	3902ED847FF28930B5F141ABFA8B471681253673
hmac sha224	    28	7A5027C4F3A358A76D943D6D83A8242675FE96E2D30A526FE9E19629
hmac sha256	    32	3ECF5388E220DA9E0F919485DEB676D8BEE3AEC046A779353B463418511EE622
hmac sha384	    48	724C212553F366248BC76017E812C8ACC85B94FEC2F396C2A925BCC2571F7AB29FEDEE6B3B3013BBF9DE7B89549D5A69
hmac sha512	    64	FC8C80E6B943CD07ECCECF01BC6038BAE68EBB6FA2E1E62B44753D7C177AF7A46B089DF349A19F7622A22312C76906CA9C984E1446D3AB86A98FDFA1425341C5
umac32     	    4	D262065C
umac64     	    8	C11564AD8F2D885E
umac96     	    12 	70C9A3F2BB7E0D993B808AE1
umac128     	16	18693CE486CF228E6B1B62EF304BFBC4
poly1305    	16	879E865A98C8CDE7C899D9A3A243EDB9
pbkdf2 sha1	    20	0C60C80F961F0E71F3A9B524AF6012062FE037A6
pbkdf2 sha256	32	89B69D0516F829893C696226650A86878C029AC13EE276509D5AE58B6466A724

aes128 encrypt	32	2EBEA9810D3056A2159BBE45A72429692EBEA9810D3056A2159BBE45A7242969
aes128 decrypt	32	aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

aes128 cbc enc	32	D3D069910C09DFC1675562A0EC9D8B204DD27DB3413D24D994F7300DD331135A
aes128 cbc dec	32	aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

aes128 ctr enc	1	64
aes128 ctr dec	1	a

aes128 eax enc	1	73
aes128 eax dgst	16	B4D34C46BFCA2E729FECC7638F9A6199
aes128 eax dec	1	a
aes128 eax dgst	16	B4D34C46BFCA2E729FECC7638F9A6199

aes128 gcm enc	1	BB
aes128 gcm dgst	16	18D5F5CCECB218322F21005BCBFF16E0
aes128 gcm dec	1	a
aes128 gcm dgst	16	18D5F5CCECB218322F21005BCBFF16E0

aes128 ccm enc	1	6E
aes128 ccm dgst	16	415B65935A4B546B9E81C988B9C68E53
aes128 ccm dec	1	a
aes128 ccm dgst	16	415B65935A4B546B9E81C988B9C68E53

aes192 encrypt	16	E21AE894602E835C9A21A6CBC5BDC030
aes192 decrypt	16	a

aes192 cbc enc	16	896A1B518F24B9FC5C5765BF102DB40A
aes192 cbc dec	16	a

aes192 ctr enc	1	98
aes192 ctr dec	1	a

aes192 gcm enc	1	1B
aes192 gcm dgst	16	8F616E7FF9A858FBDC2C1C4C302C4747
aes192 gcm dec	1	a
aes192 gcm dgst	16	8F616E7FF9A858FBDC2C1C4C302C4747

aes192 ccm enc	1	CD
aes192 ccm dgst	16	0D19B5B3D3B637D240B48BDE79395B94
aes192 ccm dec	1	a
aes192 ccm dgst	16	0D19B5B3D3B637D240B48BDE79395B94

aes256 encrypt	16	A18335BBBFFBA0996D6B7E36FBC8C0D4
aes256 decrypt	16	a

aes256 cbc enc	16	55A88E8F506DA90A694059A3A2F22E77
aes256 cbc dec	16	a

aes256 ctr enc	1	70
aes256 ctr dec	1	a

aes256 gcm enc	1	3B
aes256 gcm dgst	16	EFB12AF268F64A602779EAE2F8C2FA03
aes256 gcm dec	1	a
aes256 gcm dgst	16	EFB12AF268F64A602779EAE2F8C2FA03

aes256 ccm enc	1	A1
aes256 ccm dgst	16	B743659EF6F2FB95C77870FE3F9BD297
aes256 ccm dec	1	a
aes256 ccm dgst	16	B743659EF6F2FB95C77870FE3F9BD297

cam128 encrypt	16	FE50E0F47DF41615C2C5DC042F75B1AC
cam128 decrypt	16	a

cam128 gcm enc	1	E0
cam128 gcm dgst	16	AF2E1CC47D3D31CCC3EA63F417DF35DD
cam128 gcm dec	1	a
cam128 gcm dgst	16	AF2E1CC47D3D31CCC3EA63F417DF35DD

cam192 encrypt	16	3870F36C308368F14B4EDFFF1C577811
cam192 decrypt	16	a

cam256 encrypt	16	B2572D8BFEF8199B241C0B1008D8506B
cam256 decrypt	16	a

cam256 gcm enc	1	A0
cam256 gcm dgst	16	6B1891EE8E1F20FA49788E75A8F9447F
cam256 gcm dec	1	a
cam256 gcm dgst	16	6B1891EE8E1F20FA49788E75A8F9447F

ARCFOUR encrypt	1	CF
ARCFOUR decrypt	1	a

BLOWFISH enc	8	821C2FA4533A2FD2
BLOWFISH dec	8	a

TWOFISH enc	    16	6375B41B0C29E7446D217F79A909BB4B
TWOFISH dec	    16	a

SERPENT enc	    16	0F65C1891EA2BCCA60A1AA228A84B233
SERPENT dec	    16	a

CAST128 enc	    8	FA80BC104398019E
CAST128 dec	    8	a

ChaCha enc	    1	E2
ChaCha dec	    1	a

Salsa20 128 enc	1	27
Salsa20 128 dec	1	a

Salsa20 256 enc	1	2B
Salsa20 256 dec	1	a

Sal20r12 128 e	1	C1
Sal20r12 128 d	1	a

Sal20r12 256 e	1	E8
Sal20r12 256 d	1	a

cc-p1305 enc	1	35
cc-p1305 dgst	16	94BECC3FD052F18D657B4F18521C0409
cc-p1305 dec	1	a
cc-p1305 dgst	16	94BECC3FD052F18D657B4F18521C0409

DES check   	testtest	false
DES fix     	testtest	udsuudsu
DES check   	udsuudsu	true

DES enc     	false	8	236BF47A8D784246
DES dec     	false	8	a

DES cbc enc 	false	16	3840F08DBAD6CD6DE2AF46AF2656BE48
DES cbc dec 	false	16	testtestkalakala

DES ctr enc 	false	16	AEC72E5671C9D82D343F9F721F668701
DES ctr dec 	false	16	testtestkalakala

DES3 check   	testtestkalakalatesttest	false
DES3 fix     	testtestkalakalatesttest	udsuudsukamakamaudsuudsu
DES3 check   	udsuudsukamakamaudsuudsu	true

DES3 enc     	false	8	95D3D64AEA12A4B5
DES3 dec     	false	8	a

DES3 cbc enc	false	16	C668BD2F4C1154F638A5995EC10EF184
DES3 cbc dec	false	16	testtestkalakala

DES3 ctr enc	false	16	BDD1394B141DE724ADB714DEC4D8E30F
DES3 ctr dec	false	16	testtestkalakala

BASE64 enc	    24	dGVzdHRlc3R0ZXN0dGVzdA==
BASE64 dec	    16	testtesttesttest

BASE64 enc-url	24	dGVzdHRlc3R0ZXN0dGVzdCsm
BASE64 dec-url	18	testtesttesttest+&

... rest is truncated
```

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
s256:update('st')
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
s224:update('st')
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
s512:update('st')
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
s512:update('st')
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
s512_224:update('st')
local dgst = s512_224:digest()
```

#### SHA-512/256

```lua
local hash = require "resty.nettle.sha2"
local dgst = hash('sha512_256', 'test')
-- or
local dgst = hash.sha512_256('test')
-- or
local s512_256 = hash.sha512_256.new()
s512_256:update('te')
s512_256:update('st')
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
s224:update('st')
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
s256:update('st')
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
s384:update('st')
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
s512:update('st')
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

## Asymmentric Encryption (aka Public Key Encryption)

#### RSA (only preliminary support for now)
#### DSA (not implemented yet)

## Randomness

#### Yarrow
#### Knuth LFIB (a "lagged fibonacci" pseudorandomness generator)

## ASCII Encoding

#### Base64
#### Base16

## License

`lua-resty-nettle` uses two clause BSD license.

```
Copyright (c) 2014 – 2015, Aapo Talvensaari
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
