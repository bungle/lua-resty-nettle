local ffi          = require "ffi"
local ffi_new      = ffi.new
local ffi_typeof   = ffi.typeof
local ffi_cdef     = ffi.cdef
local ffi_str      = ffi.string
local ceil         = math.ceil
local assert       = assert
local setmetatable = setmetatable
local nettle       = require "resty.nettle"

ffi_cdef[[
typedef struct serpent_ctx {
  uint32_t keys[33][4];
} SERPENT_CTX;
void nettle_serpent_set_key(struct serpent_ctx *ctx, size_t length, const uint8_t *key);
void nettle_serpent128_set_key(struct serpent_ctx *context, const uint8_t *key);
void nettle_serpent192_set_key(struct serpent_ctx *context, const uint8_t *key);
void nettle_serpent256_set_key(struct serpent_ctx *context, const uint8_t *key);
void nettle_serpent_encrypt(const struct serpent_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src);
void nettle_serpent_decrypt(const struct serpent_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src);
]]

local uint8t = ffi_typeof "uint8_t[?]"

local serpent = {}
serpent.__index = serpent

local context   = ffi_typeof "SERPENT_CTX[1]"
local setkey128 = nettle.nettle_serpent128_set_key
local setkey192 = nettle.nettle_serpent192_set_key
local setkey256 = nettle.nettle_serpent256_set_key
local encrypt   = nettle.nettle_serpent_encrypt
local decrypt   = nettle.nettle_serpent_decrypt

function serpent.new(key)
    local len = #key
    assert(len == 16 or len == 24 or len == 32, "The SERPENT supported key sizes are 128, 192, and 256 bits. 256 bits is the recommended key size.")
    local ct = ffi_new(context)
    if len == 16 then
        setkey128(ct, key)
    elseif len == 24 then
        setkey192(ct, key)
    elseif len == 32 then
        setkey256(ct, key)
    end
    return setmetatable({ context = ct }, serpent)
end

function serpent:encrypt(src)
    local len = ceil(#src / 16) * 16
    local dst = ffi_new(uint8t, len)
    encrypt(self.context, len, dst, src)
    return ffi_str(dst, len)
end

function serpent:decrypt(src)
    local len = ceil(#src / 16) * 16
    local dst = ffi_new(uint8t, len + 1)
    decrypt(self.context, len, dst, src)
    return ffi_str(dst)
end
return serpent
