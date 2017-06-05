require "resty.nettle.types.ecc"

local hogweed      = require "resty.nettle.hogweed"
local dsa          = require "resty.nettle.dsa"
local ecc          = require "resty.nettle.ecc"
local ffi          = require "ffi"
local ffi_cdef     = ffi.cdef
local setmetatable = setmetatable

ffi_cdef[[
void nettle_ecdsa_sign(const struct ecc_scalar *key, void *random_ctx, nettle_random_func *random, size_t digest_length, const uint8_t *digest, struct dsa_signature *signature);
int  nettle_ecdsa_verify(const struct ecc_point *pub, size_t length, const uint8_t *digest, const struct dsa_signature *signature);
void nettle_ecdsa_generate_keypair(struct ecc_point *pub, struct ecc_scalar *key, void *random_ctx, nettle_random_func *random);
]]

local ecdsa = { signature = dsa.signature, point = ecc.point }

ecdsa.__index = ecdsa

function ecdsa.new(point, scalar)
    return setmetatable({ point = point, scalar = scalar }, ecdsa)
end

function ecdsa:verify(digest, signature)
    if hogweed.nettle_ecdsa_verify(self.point.context, #digest, digest, signature.context or signature) ~= 1 then
        return nil, "unable to ECDSA verify"
    end
    return true
end

return ecdsa
