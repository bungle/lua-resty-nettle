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
typedef struct twofish_ctx {
  uint32_t keys[40];
  uint32_t s_box[4][256];
} TWOFISH_CTX;
void nettle_twofish_set_key(struct twofish_ctx *ctx, size_t length, const uint8_t *key);
void nettle_twofish128_set_key(struct twofish_ctx *context, const uint8_t *key);
void nettle_twofish192_set_key(struct twofish_ctx *context, const uint8_t *key);
void nettle_twofish256_set_key(struct twofish_ctx *context, const uint8_t *key);
void nettle_twofish_encrypt(const struct twofish_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src);
void nettle_twofish_decrypt(const struct twofish_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src);
]]

local uint8t = ffi_typeof "uint8_t[?]"

local twofish = {}
twofish.__index = twofish

local context   = ffi_typeof "TWOFISH_CTX[1]"
local setkey128 = nettle.nettle_twofish128_set_key
local setkey192 = nettle.nettle_twofish192_set_key
local setkey256 = nettle.nettle_twofish256_set_key
local encrypt   = nettle.nettle_twofish_encrypt
local decrypt   = nettle.nettle_twofish_decrypt

function twofish.new(key)
    local len = #key
    assert(len == 16 or len == 24 or len == 32, "The TWOFISH supported key sizes are 128, 192, and 256 bits.")
    local ct = ffi_new(context)
    if len == 16 then
        setkey128(ct, key)
    elseif len == 24 then
        setkey192(ct, key)
    elseif len == 32 then
        setkey256(ct, key)
    end
    return setmetatable({ context = ct }, twofish)
end

function twofish:encrypt(src)
    local len = ceil(#src / 16) * 16
    local dst = ffi_new(uint8t, len)
    encrypt(self.context, len, dst, src)
    return ffi_str(dst, len)
end

function twofish:decrypt(src)
    local len = ceil(#src / 16) * 16
    local dst = ffi_new(uint8t, len + 1)
    decrypt(self.context, len, dst, src)
    return ffi_str(dst)
end
return twofish
