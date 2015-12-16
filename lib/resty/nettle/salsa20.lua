local ffi          = require "ffi"
local ffi_new      = ffi.new
local ffi_typeof   = ffi.typeof
local ffi_cdef     = ffi.cdef
local ffi_str      = ffi.string
local assert       = assert
local setmetatable = setmetatable
local nettle       = require "resty.nettle"

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
local setkey128 = nettle.nettle_salsa20_128_set_key
local setkey256 = nettle.nettle_salsa20_256_set_key
local setnonce  = nettle.nettle_salsa20_set_nonce
local crypt     = nettle.nettle_salsa20_crypt
local crypt12   = nettle.nettle_salsa20r12_crypt

local salsa20r12 = {}
salsa20r12.__index = salsa20r12

function salsa20r12:encrypt(src)
    local len = #src
    local dst = ffi_new(uint8t, len)
    crypt12(self.context, len, dst, src)
    return ffi_str(dst, len)
end

function salsa20r12:decrypt(src)
    local len = #src
    local dst = ffi_new(uint8t, len)
    crypt12(self.context, len, dst, src)
    return ffi_str(dst, len)
end

local salsa20 = {}
salsa20.__index = salsa20

function salsa20.new(key, nonce, rounds)
    local len = #key
    assert(len == 16 or len == 32, "The Salsa20 supported key sizes are 128, and 256 bits.")
    local ctx = ffi_new(ctxs20)
    if len == 16 then
        setkey128(ctx, key)
    else
        setkey256(ctx, key)
    end
    if nonce then
        assert(#nonce == 8, "The Salsa20 supported nonce size is 64 bits.")
        setnonce(ctx, nonce)
    end
    rounds = rounds or 20
    assert(rounds == 12 or rounds == 20, "The Salsa20 supported rounds are 12, and 20. The recommended rounds is 20.")
    if rounds == 20 then return setmetatable({ context = ctx }, salsa20) end
    return setmetatable({ context = ctx }, salsa20r12)
end

function salsa20:encrypt(src)
    local len = #src
    local dst = ffi_new(uint8t, len)
    crypt(self.context, len, dst, src)
    return ffi_str(dst, len)
end

function salsa20:decrypt(src)
    local len = #src
    local dst = ffi_new(uint8t, len)
    crypt(self.context, len, dst, src)
    return ffi_str(dst, len)
end

return salsa20