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
typedef struct cast128_ctx {
  unsigned rounds;
  unsigned char Kr[16];
  uint32_t Km[16];
} CAST128_CTX;
void nettle_cast5_set_key(struct cast128_ctx *ctx, size_t length, const uint8_t *key);
void nettle_cast128_set_key(struct cast128_ctx *ctx, const uint8_t *key);
void nettle_cast128_encrypt(const struct cast128_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src);
void nettle_cast128_decrypt(const struct cast128_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src);
]]

local uint8t = ffi_typeof "uint8_t[?]"

local cast128 = {}
cast128.__index = cast128

local context   = ffi_typeof "CAST128_CTX[1]"
local setkey    = lib.nettle_cast5_set_key
local setkey128 = lib.nettle_cast128_set_key
local encrypt   = lib.nettle_cast128_encrypt
local decrypt   = lib.nettle_cast128_decrypt

function cast128.new(key)
    local len = #key
    if len < 5 or len > 16 then
        return nil, "the CAST128 supported key sizes are between 40 and 128 bits"
    end
    local ct = ffi_new(context)
    if len == 16 then
        setkey128(ct, key)
    else
        setkey(ct, len, key)
    end
    return setmetatable({ context = ct }, cast128)
end

function cast128:encrypt(src, len)
    len = len or #src
    local dln = ceil(len / 8) * 8
    local dst = ffi_new(uint8t, dln)
    ffi_copy(dst, src, len)
    encrypt(self.context, dln, dst, dst)
    return ffi_str(dst, dln)
end

function cast128:decrypt(src, len)
    len = len or #src
    local dln = ceil(len / 8) * 8
    local dst = ffi_new(uint8t, dln)
    decrypt(self.context, dln, dst, src)
    return ffi_str(dst, len)
end
return cast128
