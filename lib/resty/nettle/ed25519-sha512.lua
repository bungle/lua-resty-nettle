local ffi          = require "ffi"
local ffi_new      = ffi.new
local ffi_cdef     = ffi.cdef
local ffi_str      = ffi.string
local ffi_typeof   = ffi.typeof
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
    if #pri ~= 32 then
        return nil, "The EdDSA25519 SHA-512 supported key size is 256 bits."
    end
    hogweed.nettle_ed25519_sha512_public_key(pub, pri)
    return ffi_str(pub, 32)
end

function ed.sign(pub, pri, msg)
    if #pub ~= 32 then
        return nil, "The EdDSA25519 SHA-512 supported public key size is 256 bits."
    end
    if #pri ~= 32  then
        return nil, "The EdDSA25519 SHA-512 supported private key size is 256 bits."
    end
    hogweed.nettle_ed25519_sha512_sign(pub, pri, #msg, msg, sig)
    return ffi_str(sig, 64)
end

function ed.verify(pub, msg, sig)
    if #pub ~= 32 then
        return nil, "The EdDSA25519 SHA-512 supported public key size is 256 bits."
    end
    if #sig ~= 64 then
        return nil, "The EdDSA25519 SHA-512 supported signature size is 256 bits."
    end
    if hogweed.nettle_ed25519_sha512_verify(pub, #msg, msg, sig) ~= 1 then
        return nil, "Unable to EdDSA25519 SHA-512 verify."
    end
    return true
end

return ed
