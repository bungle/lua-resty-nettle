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
typedef struct blowfish_ctx {
  uint32_t s[4][256];
  uint32_t p[18];
} BLOWFISH_CTX;
int  nettle_blowfish_set_key(struct blowfish_ctx *ctx, size_t length, const uint8_t *key);
int  nettle_blowfish128_set_key(struct blowfish_ctx *ctx, const uint8_t *key);
void nettle_blowfish_encrypt(const struct blowfish_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src);
void nettle_blowfish_decrypt(const struct blowfish_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src);
]]

local uint8t = ffi_typeof "uint8_t[?]"

local blowfish = {}
blowfish.__index = blowfish

local context = ffi_typeof "BLOWFISH_CTX[1]"
local setkey  = nettle.nettle_blowfish_set_key
local encrypt = nettle.nettle_blowfish_encrypt
local decrypt = nettle.nettle_blowfish_decrypt

function blowfish.new(key)
    local len = #key
    assert(len > 7 and len < 57, "The BLOWFISH supported key sizes are between 64 and 448 bits.")
    local ct = ffi_new(context)
    local wk = setkey(ct, len, key)
    return setmetatable({ context = ct }, blowfish), wk ~= 1
end

function blowfish:encrypt(src)
    local len = ceil(#src / 8) * 8
    local dst = ffi_new(uint8t, len)
    encrypt(self.context, len, dst, src)
    return ffi_str(dst, len)
end

function blowfish:decrypt(src)
    local len = ceil(#src / 8) * 8
    local dst = ffi_new(uint8t, len + 1)
    decrypt(self.context, len, dst, src)
    return ffi_str(dst)
end
return blowfish
