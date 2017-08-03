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
typedef struct blowfish_ctx {
  uint32_t s[4][256];
  uint32_t p[18];
} NETTLE_BLOWFISH_CTX;
int  nettle_blowfish_set_key(struct blowfish_ctx *ctx, size_t length, const uint8_t *key);
int  nettle_blowfish128_set_key(struct blowfish_ctx *ctx, const uint8_t *key);
void nettle_blowfish_encrypt(const struct blowfish_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src);
void nettle_blowfish_decrypt(const struct blowfish_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src);
]]

local uint8t = ffi_typeof "uint8_t[?]"

local blowfish = {}
blowfish.__index = blowfish

local context = ffi_typeof "NETTLE_BLOWFISH_CTX[1]"
local setkey  = lib.nettle_blowfish_set_key
local encrypt = lib.nettle_blowfish_encrypt
local decrypt = lib.nettle_blowfish_decrypt

function blowfish.new(key)
    local len = #key
    if len < 8 or len > 56 then
        return nil, "the BLOWFISH supported key sizes are between 64 and 448 bits"
    end
    local ct = ffi_new(context)
    local wk = setkey(ct, len, key)
    return setmetatable({ context = ct }, blowfish), wk ~= 1
end

function blowfish:encrypt(src, len)
    len = len or #src
    local dln = ceil(len / 8) * 8
    local dst = ffi_new(uint8t, dln)
    ffi_copy(dst, src, len)
    encrypt(self.context, dln, dst, dst)
    return ffi_str(dst, dln)
end

function blowfish:decrypt(src, len)
    len = len or #src
    local dln = ceil(len / 8) * 8
    local dst = ffi_new(uint8t, dln)
    decrypt(self.context, dln, dst, src)
    return ffi_str(dst, len)
end
return blowfish
