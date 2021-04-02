# lua-resty-nettle

LuaJIT FFI bindings for [Nettle](http://www.lysator.liu.se/~nisse/nettle/nettle.html) (a low-level cryptographic library)

## Requirements

The bindings require `libnettle`, and in some cases also `libhogweed` (comes with `libnettle`) and `gmp`.
Supported Nettle version is 3.7.x. Nettle can be downloaded from here:
[www.lysator.liu.se/~nisse/nettle/](https://www.lysator.liu.se/~nisse/nettle/).

Bindings are tested with Linux and macOS on x64 architecture, but I don't see any reason why they wouldn't work
with other platforms and architectures.


## Synopsis

```lua
local require = require
local print = print
local gsub = string.gsub
local byte = string.byte
local format = string.format
local ipairs = ipairs
local concat = table.concat

local function hex(str,spacer)
  return (gsub(str,"(.)", function (c)
    return format("%02X%s", byte(c), spacer or "")
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
  print(concat(t, '|'))
end

print()

do
  local rsa = require "resty.nettle.rsa"
  local r = rsa.new()
  local gibb = r:encrypt("fish")
  print(hex(gibb))
  local clear = r:decrypt(gibb)
  print(clear)
end

print()

do
  local ed = require "resty.nettle.ed25519-sha512"
  local pri = "testtesttesttesttesttesttesttest"
  print("EdDSA25519 SHA-512 private key", #pri, pri)
  local pub = ed.public_key(pri)
  print("EdDSA25519 SHA-512 public key", #pub, hex(pub))
  local msg = "hello"
  print("EdDSA25519 SHA-512 message", #msg, msg)
  local sig = ed.sign(pub, pri, msg)
  print("EdDSA25519 SHA-512 signature", #sig, hex(sig))
  local chk = ed.verify(pub, msg, sig)
  print("EdDSA25519 SHA-512 verify (true)", chk)
  local err = "error"
  local chk = ed.verify(pub, err, sig)
  print("EdDSA25519 SHA-512 verify (false)", chk)
end
```

The above should output this (randoms are different of course):

```text
md2      	16	8350E5A3E24C153DF2275C9F80692773
md2     	16	8350E5A3E24C153DF2275C9F80692773
md4      	16	31D6CFE0D16AE931B73C59D7E0C089C0
md4      	16	31D6CFE0D16AE931B73C59D7E0C089C0
md5      	16	D41D8CD98F00B204E9800998ECF8427E
md5      	16	D41D8CD98F00B204E9800998ECF8427E
ripemd160	20	9C1185A5C5E9FC54612808977EE8F548B2258D31
gosthash94	32	CE85B99CC46752FFFEE35CAB9A7B0278ABB4C2D2055CFF685AF4912C49490F8D
sha1      	20	DA39A3EE5E6B4B0D3255BFEF95601890AFD80709
sha1     	20	DA39A3EE5E6B4B0D3255BFEF95601890AFD80709
sha224      	28	D14A028C2A3A2BC9476102BB288234C415A2B01F828EA62AC5B3E42F
sha224      	28	D14A028C2A3A2BC9476102BB288234C415A2B01F828EA62AC5B3E42F
sha256      	32	E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855
sha256      	32	E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855
sha384      	48	38B060A751AC96384CD9327EB1B1E36A21FDB71114BE07434C0CC7BF63F6E1DA274EDEBFE76F65FBD51AD2F14898B95B
sha384      	48	38B060A751AC96384CD9327EB1B1E36A21FDB71114BE07434C0CC7BF63F6E1DA274EDEBFE76F65FBD51AD2F14898B95B
sha512      	64	CF83E1357EEFB8BDF1542850D66D8007D620E4050B5715DC83F4A921D36CE9CE47D0D13C5D85F2B0FF8318D2877EEC2F63B931BD47417A81A538327AF927DA3E
sha512      	64	CF83E1357EEFB8BDF1542850D66D8007D620E4050B5715DC83F4A921D36CE9CE47D0D13C5D85F2B0FF8318D2877EEC2F63B931BD47417A81A538327AF927DA3E
sha512_224	28	6ED0DD02806FA89E25DE060C19D3AC86CABB87D6A0DDD05C333B84F4
sha512_224	28	6ED0DD02806FA89E25DE060C19D3AC86CABB87D6A0DDD05C333B84F4
sha512_256	32	C672B8D1EF56ED28AB87C3622C5114069BDD3AD7B8F9737498D0C01ECEF0967A
sha512_256	32	C672B8D1EF56ED28AB87C3622C5114069BDD3AD7B8F9737498D0C01ECEF0967A
sha3 224	28	6B4E03423667DBB73B6E15454F0EB1ABD4597F9A1B078E3F5B5A6BC7
sha3 256	32	A7FFC6F8BF1ED76651C14756A061D662F580FF4DE43B49FA82D80A4B80F8434A
sha3 384	48	0C63A75B845E4F7D01107D852E4C2485C51A50AAAA94FC61995E71BBEE983A2AC3713831264ADB47FB6BD1E058D5F004
sha3 512	64	A69F73CCA23A9AC5C8B567DC185A756E97C982164FE25859E0D1DCC1475C80A615B2123AF1F5F94C11E3E9402C3AC558F500199D95B6D3E301758586281DCD26
hmac md5	16	06F30DC9049F859EA0CCB39FDC8FD5C2
hmac md5	16	06F30DC9049F859EA0CCB39FDC8FD5C2
hmac md5	16	06F30DC9049F859EA0CCB39FDC8FD5C2
hmac ripemd160	20	ECB2E5CA0EEFFD84F5566B5DE1D037EF1F9689EF
hmac sha1	20	3902ED847FF28930B5F141ABFA8B471681253673
hmac sha224	28	7A5027C4F3A358A76D943D6D83A8242675FE96E2D30A526FE9E19629
hmac sha256	32	3ECF5388E220DA9E0F919485DEB676D8BEE3AEC046A779353B463418511EE622
hmac sha384	48	724C212553F366248BC76017E812C8ACC85B94FEC2F396C2A925BCC2571F7AB29FEDEE6B3B3013BBF9DE7B89549D5A69
hmac sha512	64	FC8C80E6B943CD07ECCECF01BC6038BAE68EBB6FA2E1E62B44753D7C177AF7A46B089DF349A19F7622A22312C76906CA9C984E1446D3AB86A98FDFA1425341C5
umac32     	4	D262065C
umac64     	8	DA7E5EB7E37A27E6
umac96     	12	6B8FBA819AB2FEFA8A18F5AA
umac128     	16	D55988EE39924D7642FFB401A79BCE29
poly1305    	16	879E865A98C8CDE7C899D9A3A243EDB9
pbkdf2 sha1	20	0C60C80F961F0E71F3A9B524AF6012062FE037A6
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

TWOFISH enc	16	6375B41B0C29E7446D217F79A909BB4B
TWOFISH dec	16	a

SERPENT enc	16	0F65C1891EA2BCCA60A1AA228A84B233
SERPENT dec	16	a

CAST128 enc	8	FA80BC104398019E
CAST128 dec	8	a

ChaCha enc	1	E2
ChaCha dec	1	a

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

BASE64 enc	24	dGVzdHRlc3R0ZXN0dGVzdA==
BASE64 dec	16	testtesttesttest

BASE64 enc-url	24	dGVzdHRlc3R0ZXN0dGVzdCsm
BASE64 dec-url	18	testtesttesttest+&

d	1
G	1
Vz	2
d	1
HRlc3	5
R0	2
Z	1
X	1
N0	2
dGVzd	5
A==	3

	0
t	1
e	1
s	1
	0
ttes	4
t	1
t	1
	0
e	1
s	1
t	1
test	4
true

BASE16 enc	32	74657374746573747465737474657374
BASE16 dec	16	testtesttesttest

74
65
73
74
74657374
74
65
73
74
74657374

	0
t	1
	0
e	1
	0
s	1
	0
t	1
test	4
	0
t	1
	0
e	1
	0
s	1
	0
t	1
test	4
true

2
false
true
5DBE3C56BEDDA2608DD6D0924902271A7CE0A9C81EF955E396594329306A
0D3CE56865CF002F7A53914C58D6C8037904C82E3D72ED1E5F09D0178A93
5114614E5779289597D9DC54EF2716531A6543718ED8F26CE850632E4B46
7D0D2C1F5D5C4D59F4C07115A5B0E0AED2BA6FF406AE9A85412EB62091E6

1028764519
765133839
DC1424283A03BA0C01E9
584484306|437203720|985724606|714176836|864733948|650443754|198142580|632065637|974210952|193718333

411CFFB5C68DC3BA80CE5A72E127A5E06B1AEB7820BCEE14C738708DC048F8889CD3A86E16379F6E56DACF941C0841CA2C7B948D336CD5E529587383B2C03438C60B4BBE3BB2D3CF7CCB25BC9260FEA7C6117CC9E0D289DA0D85614CFBAEB33590AD43CF8C65802B794F160E04AFB98B883887E7A290AB3E2EFEF46D5D6D760E78904CAF3BBCE8ADC3C3B400012D06AB40032B2BB4689DF84A1AB0AB8CF72B89BDC8F1A572270B8A8A4C5C61DA01FADC1F5D9DCF70BD6E1C3A79990467295D32DF4182C8EC81A4C2050DFAB419102393886920D40FD5DE5AA6CC4E435F70A9341B849266B092E3C3C33623C34262C907A9FB92A1A480B87E6E375E9DE96D104CFF6A97800BD8B9F2C454FC99D9FF400865EFC8CE882F50BA9488DB47A071311EB0B1CC3F6D477A39098F2714F92229B4497AE78DC6477BBF1705071C58B459F907C3D7D82727A7FA87C3ECEA1EACE01B92341FC93499AC00C1473721E4EED81B39C7635BC810C516BDD0F184B19AE8C92BE4E025419E01DA5A2CA712375EA0BA9C3D9E35BC57AB24FA695B8685E5BE570BC8148CAF5BF0C3AFA74F588080E60DFDE821B1271FE7F111831DE64E39F12FF309298E57819D1B284A29349707DB5D7BD9604FA433FBF0B718CC9B15B02AB9AA34C53ECBBE759018AC9D3251EEEA8CE6CCAC56AA1402FB078A7A3E802554BEDACF8F7976CFC68EAC8DA06FD6FA4CE1
fish

EdDSA25519 SHA-512 private key	32	testtesttesttesttesttesttesttest
EdDSA25519 SHA-512 public key	32	06B77FC89D2B9785433DD37A9B98A3C8FA37F03DB2B2CC0E79BE76F87B223D21
EdDSA25519 SHA-512 message	5	hello
EdDSA25519 SHA-512 signature	64	0E202379D19190BC1A933D3DD1753FF0B833393BEED1DC12469309F2A07094348E340C302069CDB7C7C54C21CCDA8891F21FA4588D63803C9538F2A513DA6E04
EdDSA25519 SHA-512 verify (true)	true
EdDSA25519 SHA-512 verify (false)	nil
```

## Installation

Just place [`nettle.lua`](https://github.com/bungle/lua-resty-nettle/blob/master/lib/resty/nettle.lua) and [`nettle`](https://github.com/bungle/lua-resty-nettle/tree/master/lib/resty/nettle) directory somewhere in your `package.path`, under `resty` directory. If you are using OpenResty, the default location would be `/usr/local/openresty/lualib/resty`.

### Using OpenResty Package Manager (opm)

```Shell
$ opm get bungle/lua-resty-nettle
```

### Using LuaRocks

```Shell
$ luarocks install lua-resty-nettle
```

LuaRocks repository for `lua-resty-nettle` is located at https://luarocks.org/modules/bungle/lua-resty-nettle.

## Hash Functions

#### SHA-224

```lua
local hash = require "resty.nettle.sha2"
local dgst = hash("sha224", "test")
-- or
local dgst = hash.sha224 "test"
-- or
local sha2 = hash.sha224..new()
sha2:update "te"
sha2:update "st"
local dgst = sha2:digest()
```

#### SHA-256

```lua
local hash = require "resty.nettle.sha2"
local dgst = hash("sha256", "test")
-- or
local dgst = hash.sha256 "test"
-- or
local sha2 = hash.sha256.new()
sha2:update "te"
sha2:update "st"
local dgst = sha2:digest()
```

#### SHA-384

```lua
local hash = require "resty.nettle.sha2"
local dgst = hash("sha384", "test")
-- or
local dgst = hash.sha384 "test"
-- or
local sha2 = hash.sha384.new()
sha2:update "te"
sha2:update "st"
local dgst = sha2:digest()
```

#### SHA-512

```lua
local hash = require "resty.nettle.sha2"
local dgst = hash("sha512", "test")
-- or
local dgst = hash.sha512 "test"
-- or
local sha2 = hash.sha512.new()
sha2:update "te"
sha2:update "st"
local dgst = sha2:digest()
```

#### SHA-512/224

```lua
local hash = require "resty.nettle.sha2"
local dgst = hash("sha512_224", "test")
-- or
local dgst = hash.sha512_224 "test"
-- or
local sha2 = hash.sha512_224.new()
sha2:update "te"
sha2:update "st"
local dgst = sha2:digest()
```

#### SHA-512/256

```lua
local hash = require "resty.nettle.sha2"
local dgst = hash("sha512_256", "test")
-- or
local dgst = hash.sha512_256 "test"
-- or
local sha2 = hash.sha512_256.new()
sha2:update "te"
sha2:update "st"
local dgst = sha2:digest()
```

#### SHA3-224

```lua
local hash = require "resty.nettle.sha3"
local dgst = hash(224, "test")
-- or
local dgst = hash.sha224 "test"
-- or
local sha3 = hash.sha224.new()
sha3:update "te"
sha3:update "st"
local dgst = sha3:digest()
```

#### SHA3-256

```lua
local hash = require "resty.nettle.sha3"
local dgst = hash(256, "test")
-- or
local dgst = hash.sha256 "test"
-- or
local sha3 = hash.sha256.new()
sha3:update "te"
sha3:update "st"
local dgst = sha3:digest()
```

#### SHA3-384

```lua
local hash = require "resty.nettle.sha3"
local dgst = hash(384, "test")
-- or
local dgst = hash.sha384 "test"
-- or
local sha3 = hash.sha384.new()
sha3:update "te"
sha3:update "st"
local dgst = sha3:digest()
```

#### SHA3-512

```lua
local hash = require "resty.nettle.sha3"
local dgst = hash(512, "test")
-- or
local dgst = hash.sha512 "test"
-- or
local sha3 = hash.sha512.new()
sha3:update "te"
sha3:update "st"
local dgst = sha3:digest()
```

#### MD2

```lua
local hash = require "resty.nettle.md2"
local dgst = hash "test"
-- or
local md2 = hash.new()
md2:update "te"
md2:update "st"
local dgst = md2:digest()
```

#### MD4

```lua
local hash = require "resty.nettle.md4"
local dgst = hash "test"
-- or
local md4 = hash.new()
md4:update "te"
md4:update "st"
local dgst = md4:digest()
```

#### MD5

```lua
local hash = require "resty.nettle.md5"
local dgst = hash "test"
-- or
local md5 = hash.new()
md5:update "te"
md5:update "st"
local dgst = md5:digest()
```

#### RIPEMD160

```lua
local hash = require "resty.nettle.ripemd160"
local dgst = hash "test"
-- or
local ripe = hash.new()
ripe:update "te"
ripe:update "st"
local dgst = ripe:digest()
```

#### SHA-1

```lua
local hash = require "resty.nettle.sha1"
local dgst = hash "test"
-- or
local sha1 = hash.new()
sha1:update "te"
sha1:update "st"
local dgst = sha1:digest()
```

#### GOSTHASH94

```lua
local hash = require "resty.nettle.gosthash94"
local dgst = hash "test"
-- or
local gh94 = hash.new()
gh94:update "te"
gh94:update "st"
local dgst = gh94:digest()
```

## Keyed Hash Functions

#### HMAC-MD5
#### HMAC-RIPEMD160
#### HMAC-SHA1
#### HMAC-SHA256
#### HMAC-SHA512
#### UMAC
#### CMAC
#### Poly1305

## Key Derivation Functions

#### HKDF
#### PBKDF2-HMAC-SHA1
#### PBKDF2-HMAC-SHA256

## Cipher Functions

#### AES
#### ARCFOUR
#### ARCTWO
#### BLOWFISH
#### Camellia
#### CAST128
#### ChaCha
#### DES
#### DES3
#### Salsa20
#### SERPENT
#### TWOFISH

## Cipher Modes

#### Cipher Block Chaining (CBC)
#### Counter Mode (CTR)
#### Cipher Feedback Mode (CFB)
#### XEX-based tweaked-codebook Mode with Ciphertext Stealing (XTS)

## Authenticated Encryption with Associated Data

#### EAX
#### Galois Counter Mode (GCM)
#### Counter with CBC-MAC Mode (CCM)
#### ChaCha-Poly1305

## Asymmentric Encryption (aka Public Key Encryption)

#### RSA
#### RSA PSS
#### DSA
#### ECDSA
#### EdDSA

## Randomness

#### Yarrow
#### Knuth LFIB (a "lagged fibonacci" pseudorandomness generator)

## ASCII Encoding

#### Base64
#### Base16

## Changes

The changes of every release of this module is recorded in [Changes.md](https://github.com/bungle/lua-resty-nettle/blob/master/Changes.md) file.

## License

`lua-resty-nettle` uses two clause BSD license.

```
Copyright (c) 2014 – 2021, Aapo Talvensaari
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
