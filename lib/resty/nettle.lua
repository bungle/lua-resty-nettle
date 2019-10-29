return {
  _VERSION            = "1.0",
  aes                 = require "resty.nettle.aes",
  arcfour             = require "resty.nettle.arcfour",
  base16              = require "resty.nettle.base16",
  base64              = require "resty.nettle.base64",
  blowfish            = require "resty.nettle.blowfish",
  camellia            = require "resty.nettle.camellia",
  cast128             = require "resty.nettle.cast128",
  chacha              = require "resty.nettle.chacha",
  chacha_poly1305     = require "resty.nettle.chacha-poly1305",
  ["chacha-poly1305"] = require "resty.nettle.chacha-poly1305",
  cmac                = require "resty.nettle.cmac",
  curve25519          = require "resty.nettle.curve25519",
  des                 = require "resty.nettle.des",
  dsa                 = require "resty.nettle.dsa",
  ecc                 = require "resty.nettle.ecc",
  ecdsa               = require "resty.nettle.ecdsa",
  ed25519_sha512      = require "resty.nettle.ed25519-sha512",
  ["ed25519-sha512"]  = require "resty.nettle.ed25519-sha512",
  gmp                 = require "resty.nettle.gmp",
  gosthash94          = require "resty.nettle.gosthash94",
  hmac                = require "resty.nettle.hmac",
  hogweed             = require "resty.nettle.hogweed",
  knuth_lfib          = require "resty.nettle.knuth-lfib",
  ["knuth-lfib"]      = require "resty.nettle.knuth-lfib",
  library             = require "resty.nettle.library",
  md2                 = require "resty.nettle.md2",
  md4                 = require "resty.nettle.md4",
  md5                 = require "resty.nettle.md5",
  mpz                 = require "resty.nettle.mpz",
  padding             = require "resty.nettle.padding",
  pbkdf2              = require "resty.nettle.pbkdf2",
  poly1305            = require "resty.nettle.poly1305",
  random              = require "resty.nettle.random",
  rc4                 = require "resty.nettle.rc4",
  ripemd160           = require "resty.nettle.ripemd160",
  rsa                 = require "resty.nettle.rsa",
  salsa20             = require "resty.nettle.salsa20",
  serpent             = require "resty.nettle.serpent",
  sha1                = require "resty.nettle.sha1",
  sha2                = require "resty.nettle.sha2",
  sha3                = require "resty.nettle.sha3",
  twofish             = require "resty.nettle.twofish",
  umac                = require "resty.nettle.umac",
  version             = require "resty.nettle.version",
  yarrow              = require "resty.nettle.yarrow",
}
