rockspec_format = "3.0"
package = "lua-resty-nettle"
version = "dev-1"
source = {
  url = "git://github.com/bungle/lua-resty-nettle.git",
}
description = {
  summary    = "LuaJIT FFI bindings for Nettle (a low-level cryptographic library)",
  detailed   = "lua-resty-nettle contains LuaJIT FFI bindings to GNU Nettle cryptographic library.",
  homepage   = "https://github.com/bungle/lua-resty-nettle",
  issues_url = "https://github.com/bungle/lua-resty-nettle/issues",
  maintainer = "Aapo Talvensaari <aapo.talvensaari@gmail.com>",
  license    = "BSD",
  labels     = {
    "crypto",
  },
}
dependencies = {
  "lua >= 5.1",
}
build = {
  type = "builtin",
  modules = {
    ["resty.nettle"]                       = "lib/resty/nettle.lua",
    ["resty.nettle.aes"]                   = "lib/resty/nettle/aes.lua",
    ["resty.nettle.arcfour"]               = "lib/resty/nettle/arcfour.lua",
    ["resty.nettle.arctwo"]                = "lib/resty/nettle/arctwo.lua",
    ["resty.nettle.base16"]                = "lib/resty/nettle/base16.lua",
    ["resty.nettle.base64"]                = "lib/resty/nettle/base64.lua",
    ["resty.nettle.bcrypt"]                = "lib/resty/nettle/bcrypt.lua",
    ["resty.nettle.blowfish"]              = "lib/resty/nettle/blowfish.lua",
    ["resty.nettle.camellia"]              = "lib/resty/nettle/camellia.lua",
    ["resty.nettle.cast128"]               = "lib/resty/nettle/cast128.lua",
    ["resty.nettle.chacha"]                = "lib/resty/nettle/chacha.lua",
    ["resty.nettle.chacha-poly1305"]       = "lib/resty/nettle/chacha-poly1305.lua",
    ["resty.nettle.cmac"]                  = "lib/resty/nettle/cmac.lua",
    ["resty.nettle.curve448"]              = "lib/resty/nettle/curve448.lua",
    ["resty.nettle.curve25519"]            = "lib/resty/nettle/curve25519.lua",
    ["resty.nettle.des"]                   = "lib/resty/nettle/des.lua",
    ["resty.nettle.dsa"]                   = "lib/resty/nettle/dsa.lua",
    ["resty.nettle.ecc"]                   = "lib/resty/nettle/ecc.lua",
    ["resty.nettle.ecdsa"]                 = "lib/resty/nettle/ecdsa.lua",
    ["resty.nettle.ed448-shake256"]        = "lib/resty/nettle/ed448-shake256.lua",
    ["resty.nettle.ed25519-sha512"]        = "lib/resty/nettle/ed25519-sha512.lua",
    ["resty.nettle.eddsa"]                 = "lib/resty/nettle/eddsa.lua",
    ["resty.nettle.gmp"]                   = "lib/resty/nettle/gmp.lua",
    ["resty.nettle.gosthash94"]            = "lib/resty/nettle/gosthash94.lua",
    ["resty.nettle.gosthash94cp"]          = "lib/resty/nettle/gosthash94cp.lua",
    ["resty.nettle.hmac"]                  = "lib/resty/nettle/hmac.lua",
    ["resty.nettle.hogweed"]               = "lib/resty/nettle/hogweed.lua",
    ["resty.nettle.knuth-lfib"]            = "lib/resty/nettle/knuth-lfib.lua",
    ["resty.nettle.library"]               = "lib/resty/nettle/library.lua",
    ["resty.nettle.md2"]                   = "lib/resty/nettle/md2.lua",
    ["resty.nettle.md4"]                   = "lib/resty/nettle/md4.lua",
    ["resty.nettle.md5"]                   = "lib/resty/nettle/md5.lua",
    ["resty.nettle.mpz"]                   = "lib/resty/nettle/mpz.lua",
    ["resty.nettle.padding"]               = "lib/resty/nettle/padding.lua",
    ["resty.nettle.pbkdf2"]                = "lib/resty/nettle/pbkdf2.lua",
    ["resty.nettle.poly1305"]              = "lib/resty/nettle/poly1305.lua",
    ["resty.nettle.random"]                = "lib/resty/nettle/random.lua",
    ["resty.nettle.rc2"]                   = "lib/resty/nettle/rc2.lua",
    ["resty.nettle.rc4"]                   = "lib/resty/nettle/rc4.lua",
    ["resty.nettle.ripemd160"]             = "lib/resty/nettle/ripemd160.lua",
    ["resty.nettle.rsa"]                   = "lib/resty/nettle/rsa.lua",
    ["resty.nettle.salsa20"]               = "lib/resty/nettle/salsa20.lua",
    ["resty.nettle.serpent"]               = "lib/resty/nettle/serpent.lua",
    ["resty.nettle.sha1"]                  = "lib/resty/nettle/sha1.lua",
    ["resty.nettle.sha2"]                  = "lib/resty/nettle/sha2.lua",
    ["resty.nettle.sha3"]                  = "lib/resty/nettle/sha3.lua",
    ["resty.nettle.sha3-shake"]            = "lib/resty/nettle/sha3-shake.lua",
    ["resty.nettle.streebog"]              = "lib/resty/nettle/streebog.lua",
    ["resty.nettle.twofish"]               = "lib/resty/nettle/twofish.lua",
    ["resty.nettle.umac"]                  = "lib/resty/nettle/umac.lua",
    ["resty.nettle.version"]               = "lib/resty/nettle/version.lua",
    ["resty.nettle.yarrow"]                = "lib/resty/nettle/yarrow.lua",
    ["resty.nettle.types.aes"]             = "lib/resty/nettle/types/aes.lua",
    ["resty.nettle.types.arcfour"]         = "lib/resty/nettle/types/arcfour.lua",
    ["resty.nettle.types.arctwo"]          = "lib/resty/nettle/types/arctwo.lua",
    ["resty.nettle.types.base16"]          = "lib/resty/nettle/types/base16.lua",
    ["resty.nettle.types.base64"]          = "lib/resty/nettle/types/base64.lua",
    ["resty.nettle.types.bcrypt"]          = "lib/resty/nettle/types/bcrypt.lua",
    ["resty.nettle.types.blowfish"]        = "lib/resty/nettle/types/blowfish.lua",
    ["resty.nettle.types.camellia"]        = "lib/resty/nettle/types/camellia.lua",
    ["resty.nettle.types.cast128"]         = "lib/resty/nettle/types/cast128.lua",
    ["resty.nettle.types.cbc"]             = "lib/resty/nettle/types/cbc.lua",
    ["resty.nettle.types.ccm"]             = "lib/resty/nettle/types/ccm.lua",
    ["resty.nettle.types.cfb"]             = "lib/resty/nettle/types/cfb.lua",
    ["resty.nettle.types.chacha"]          = "lib/resty/nettle/types/chacha.lua",
    ["resty.nettle.types.chacha-poly1305"] = "lib/resty/nettle/types/chacha-poly1305.lua",
    ["resty.nettle.types.cmac"]            = "lib/resty/nettle/types/cmac.lua",
    ["resty.nettle.types.common"]          = "lib/resty/nettle/types/common.lua",
    ["resty.nettle.types.ctr"]             = "lib/resty/nettle/types/ctr.lua",
    ["resty.nettle.types.curve448"]        = "lib/resty/nettle/types/curve448.lua",
    ["resty.nettle.types.curve25519"]      = "lib/resty/nettle/types/curve25519.lua",
    ["resty.nettle.types.des"]             = "lib/resty/nettle/types/des.lua",
    ["resty.nettle.types.dsa"]             = "lib/resty/nettle/types/dsa.lua",
    ["resty.nettle.types.eax"]             = "lib/resty/nettle/types/eax.lua",
    ["resty.nettle.types.ecc"]             = "lib/resty/nettle/types/ecc.lua",
    ["resty.nettle.types.ecdsa"]           = "lib/resty/nettle/types/ecdsa.lua",
    ["resty.nettle.types.ed448-shake256"]  = "lib/resty/nettle/types/ed448-shake256.lua",
    ["resty.nettle.types.ed25519-sha512"]  = "lib/resty/nettle/types/ed25519-sha512.lua",
    ["resty.nettle.types.gcm"]             = "lib/resty/nettle/types/gcm.lua",
    ["resty.nettle.types.gosthash94"]      = "lib/resty/nettle/types/gosthash94.lua",
    ["resty.nettle.types.hmac"]            = "lib/resty/nettle/types/hmac.lua",
    ["resty.nettle.types.knuth-lfib"]      = "lib/resty/nettle/types/knuth-lfib.lua",
    ["resty.nettle.types.md2"]             = "lib/resty/nettle/types/md2.lua",
    ["resty.nettle.types.md4"]             = "lib/resty/nettle/types/md4.lua",
    ["resty.nettle.types.md5"]             = "lib/resty/nettle/types/md5.lua",
    ["resty.nettle.types.mpz"]             = "lib/resty/nettle/types/mpz.lua",
    ["resty.nettle.types.nettle-types"]    = "lib/resty/nettle/types/nettle-types.lua",
    ["resty.nettle.types.pbkdf2"]          = "lib/resty/nettle/types/pbkdf2.lua",
    ["resty.nettle.types.poly1305"]        = "lib/resty/nettle/types/poly1305.lua",
    ["resty.nettle.types.ripemd160"]       = "lib/resty/nettle/types/ripemd160.lua",
    ["resty.nettle.types.rsa"]             = "lib/resty/nettle/types/rsa.lua",
    ["resty.nettle.types.salsa20"]         = "lib/resty/nettle/types/salsa20.lua",
    ["resty.nettle.types.serpent"]         = "lib/resty/nettle/types/serpent.lua",
    ["resty.nettle.types.sha1"]            = "lib/resty/nettle/types/sha1.lua",
    ["resty.nettle.types.sha2"]            = "lib/resty/nettle/types/sha2.lua",
    ["resty.nettle.types.sha3"]            = "lib/resty/nettle/types/sha3.lua",
    ["resty.nettle.types.siv-cmac"]        = "lib/resty/nettle/types/siv-cmac.lua",
    ["resty.nettle.types.streebog"]        = "lib/resty/nettle/types/streebog.lua",
    ["resty.nettle.types.twofish"]         = "lib/resty/nettle/types/twofish.lua",
    ["resty.nettle.types.umac"]            = "lib/resty/nettle/types/umac.lua",
    ["resty.nettle.types.version"]         = "lib/resty/nettle/types/version.lua",
    ["resty.nettle.types.xts"]             = "lib/resty/nettle/types/xts.lua",
    ["resty.nettle.types.yarrow"]          = "lib/resty/nettle/types/yarrow.lua",
    ["resty.nettle.padding.ansix923"]      = "lib/resty/nettle/padding/ansix923.lua",
    ["resty.nettle.padding.base64"]        = "lib/resty/nettle/padding/base64.lua",
    ["resty.nettle.padding.iso7816-4"]     = "lib/resty/nettle/padding/iso7816-4.lua",
    ["resty.nettle.padding.iso10126"]      = "lib/resty/nettle/padding/iso10126.lua",
    ["resty.nettle.padding.nopadding"]     = "lib/resty/nettle/padding/nopadding.lua",
    ["resty.nettle.padding.pkcs7"]         = "lib/resty/nettle/padding/pkcs7.lua",
    ["resty.nettle.padding.spacepadding"]  = "lib/resty/nettle/padding/spacepadding.lua",
    ["resty.nettle.padding.zeropadding"]   = "lib/resty/nettle/padding/zeropadding.lua",
  }
}
