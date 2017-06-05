local lib          = require "resty.nettle.library"
local ffi          = require "ffi"
local ffi_new      = ffi.new
local ffi_typeof   = ffi.typeof
local ffi_cdef     = ffi.cdef
local ffi_copy     = ffi.copy
local ffi_str      = ffi.string
local setmetatable = setmetatable

ffi_cdef[[
typedef struct salsa20_ctx {
  uint32_t input[16];
} SALSA20_CTX;
void nettle_salsa20_128_set_key(struct salsa20_ctx *ctx, const uint8_t *key);
void nettle_salsa20_256_set_key(struct salsa20_ctx *ctx, const uint8_t *key);
void nettle_salsa20_set_nonce(struct salsa20_ctx *ctx, const uint8_t *nonce);
void nettle_salsa20_crypt(struct salsa20_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src);
void nettle_salsa20r12_crypt(struct salsa20_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src);
]]

local uint8t    = ffi_typeof "uint8_t[?]"
local ctxs20    = ffi_typeof "SALSA20_CTX[1]"
local setkey128 = lib.nettle_salsa20_128_set_key
local setkey256 = lib.nettle_salsa20_256_set_key
local setnonce  = lib.nettle_salsa20_set_nonce
local crypt     = lib.nettle_salsa20_crypt
local crypt12   = lib.nettle_salsa20r12_crypt

local salsa20r12 = {}
salsa20r12.__index = salsa20r12

function salsa20r12:encrypt(src, len)
    len = len or #src
    local dst = ffi_new(uint8t, len)
    ffi_copy(dst, src, len)
    crypt12(self.context, len, dst, dst)
    return ffi_str(dst, len)
end

function salsa20r12:decrypt(src, len)
    len = len or #src
    local dst = ffi_new(uint8t, len)
    crypt12(self.context, len, dst, src)
    return ffi_str(dst, len)
end

local salsa20 = {}
salsa20.__index = salsa20

function salsa20.new(key, nonce, rounds)
    local len = #key
    if len ~= 16 and len ~= 32 then
        return nil, "the Salsa20 supported key sizes are 128, and 256 bits"
    end
    local ctx = ffi_new(ctxs20)
    if len == 16 then
        setkey128(ctx, key)
    else
        setkey256(ctx, key)
    end
    if nonce then
        if #nonce ~= 8 then
            return nil, "the Salsa20 supported nonce size is 64 bits"
        end
        setnonce(ctx, nonce)
    end
    rounds = rounds or 20
    if rounds ~= 12 and rounds ~= 20 then
        return nil, "the Salsa20 supported rounds are 12, and 20. The recommended rounds is 20"
    end
    if rounds == 20 then return setmetatable({ context = ctx }, salsa20) end
    return setmetatable({ context = ctx }, salsa20r12)
end

function salsa20:encrypt(src, len)
    len = len or #src
    local dst = ffi_new(uint8t, len)
    ffi_copy(dst, src, len)
    crypt(self.context, len, dst, dst)
    return ffi_str(dst, len)
end

function salsa20:decrypt(src, len)
    len = len or #src
    local dst = ffi_new(uint8t, len)
    crypt(self.context, len, dst, src)
    return ffi_str(dst, len)
end

return salsa20
