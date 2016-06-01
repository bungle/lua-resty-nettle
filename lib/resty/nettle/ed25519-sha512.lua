local ffi          = require "ffi"
local ffi_new      = ffi.new
local ffi_cdef     = ffi.cdef
local ffi_str      = ffi.string
local ffi_typeof   = ffi.typeof
local assert       = assert
local hogweed      = require "resty.nettle.hogweed"

ffi_cdef[[
void nettle_ed25519_sha512_public_key(uint8_t *pub, const uint8_t *priv);
void nettle_ed25519_sha512_sign(const uint8_t *pub, const uint8_t *priv, size_t length, const uint8_t *msg, uint8_t *signature);
 int nettle_ed25519_sha512_verify(const uint8_t *pub, size_t length, const uint8_t *msg, const uint8_t *signature);
]]

local uint8t = ffi_typeof "uint8_t[?]"
local sig = ffi_new(uint8t, 64)
local pub = ffi_new(uint8t, 32)
local ed = {}

function ed.public_key(pri)
    assert(#pri == 32, "The EdDSA25519 SHA-512 supported key size is 256 bits")
    hogweed.nettle_ed25519_sha512_public_key(pub, pri)
    return ffi_str(pub, 32)
end

function ed.sign(pub, pri, msg)
    assert(#pub == 32 and #pri == 32, "The EdDSA25519 SHA-512 supported key size is 256 bits")
    hogweed.nettle_ed25519_sha512_sign(pub, pri, #msg, msg, sig)
    return ffi_str(sig, 64)
end

function ed.verify(pub, msg, sig)
    assert(#pub == 32, "The EdDSA25519 SHA-512 supported key size is 256 bits")
    assert(#sig == 64, "The EdDSA25519 SHA-512 supported signature size is 512 bits")
    return hogweed.nettle_ed25519_sha512_verify(pub, #msg, msg, sig) == 1
end

return ed