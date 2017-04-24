-- TODO: THIS IS NOT DONE, IT DOESN'T WORK YET.
require "resty.nettle.types.dsa"
require "resty.nettle.types.ecc"

local hogweed      = require "resty.nettle.library"
local ffi          = require "ffi"
local ffi_new      = ffi.new
local ffi_cdef     = ffi.cdef
local setmetatable = setmetatable

ffi_cdef[[
void nettle_ecdsa_sign(const struct ecc_scalar *key, void *random_ctx, nettle_random_func *random, size_t digest_length, const uint8_t *digest, struct dsa_signature *signature);
int  nettle_ecdsa_verify(const struct ecc_point *pub, size_t length, const uint8_t *digest, const struct dsa_signature *signature);
void nettle_ecdsa_generate_keypair(struct ecc_point *pub, struct ecc_scalar *key, void *random_ctx, nettle_random_func *random);
]]

local ecdsa = {}
ecdsa.__index = ecdsa

function ecdsa.new()
    local self = setmetatable({}, ecdsa)
    return self
end

function ecdsa.generate_keypair()

end
