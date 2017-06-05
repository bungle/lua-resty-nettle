local lib          = require "resty.nettle.library"
local ffi          = require "ffi"
local ffi_new      = ffi.new
local ffi_typeof   = ffi.typeof
local ffi_cdef     = ffi.cdef
local ffi_copy     = ffi.copy
local ffi_str      = ffi.string
local ceil         = math.ceil
local setmetatable = setmetatable

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
local setkey128 = lib.nettle_serpent128_set_key
local setkey192 = lib.nettle_serpent192_set_key
local setkey256 = lib.nettle_serpent256_set_key
local encrypt   = lib.nettle_serpent_encrypt
local decrypt   = lib.nettle_serpent_decrypt

function serpent.new(key)
    local len = #key
    if len ~= 16 and len ~= 24 and len ~= 32 then
        return nil, "the SERPENT supported key sizes are 128, 192, and 256 bits, and the 256 bits is the recommended key size"
    end
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

function serpent:encrypt(src, len)
    len = len or #src
    local dln = ceil(len / 16) * 16
    local dst = ffi_new(uint8t, dln)
    ffi_copy(dst, src, len)
    encrypt(self.context, dln, dst, dst)
    return ffi_str(dst, dln)
end

function serpent:decrypt(src, len)
    len = len or #src
    local dln = ceil(len / 16) * 16
    local dst = ffi_new(uint8t, dln)
    decrypt(self.context, dln, dst, src)
    return ffi_str(dst, len)
end
return serpent
