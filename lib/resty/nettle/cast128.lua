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
local setkey    = nettle.nettle_cast5_set_key
local setkey128 = nettle.nettle_cast128_set_key
local encrypt   = nettle.nettle_cast128_encrypt
local decrypt   = nettle.nettle_cast128_decrypt

function cast128.new(key)
    local len = #key
    assert(len > 4 and len < 17, "The CAST128 supported key sizes are between 40 and 128 bits.")
    local ct = ffi_new(context)
    if len == 16 then
        setkey128(ct, key)
    else
        setkey(ct, len, key)
    end
    return setmetatable({ context = ct }, cast128)
end

function cast128:encrypt(src)
    local len = ceil(#src / 8) * 8
    local dst = ffi_new(uint8t, len)
    encrypt(self.context, len, dst, src)
    return ffi_str(dst, len)
end

function cast128:decrypt(src)
    local len = ceil(#src / 8) * 8
    local dst = ffi_new(uint8t, len + 1)
    decrypt(self.context, len, dst, src)
    return ffi_str(dst)
end
return cast128
