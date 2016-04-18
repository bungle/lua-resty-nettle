local ffi          = require "ffi"
local ffi_new      = ffi.new
local ffi_typeof   = ffi.typeof
local ffi_cdef     = ffi.cdef
local ffi_copy     = ffi.copy
local ffi_str      = ffi.string
local assert       = assert
local setmetatable = setmetatable
local nettle       = require "resty.nettle"

ffi_cdef[[
typedef struct arcfour_ctx {
  uint8_t S[256];
  uint8_t i;
  uint8_t j;
} ARCFOUR_CTX;
void nettle_arcfour_set_key(struct arcfour_ctx *ctx, size_t length, const uint8_t *key);
void nettle_arcfour128_set_key(struct arcfour_ctx *ctx, const uint8_t *key);
void nettle_arcfour_crypt(struct arcfour_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src);
]]

local uint8t = ffi_typeof "uint8_t[?]"

local arcfour = {}
arcfour.__index = arcfour

local context  = ffi_typeof "ARCFOUR_CTX[1]"
local setkey   = nettle.nettle_arcfour_set_key
local crypt    = nettle.nettle_arcfour_crypt

function arcfour.new(key)
    local len = #key
    assert(len > 0 and len < 257, "The ARCFOUR supported key sizes are between 1 and 256 bits.")
    local ct = ffi_new(context)
    setkey(ct, len, key)
    return setmetatable({ context = ct }, arcfour)
end

function arcfour:encrypt(src, len)
    len = len or #src
    local dst = ffi_new(uint8t, len)
    ffi_copy(dst, src, len)
    crypt(self.context, len, dst, dst)
    return ffi_str(dst, len)
end

function arcfour:decrypt(src, len)
    len = len or #src
    local dst = ffi_new(uint8t, len)
    crypt(self.context, len, dst, src)
    return ffi_str(dst, len)
end

return arcfour
