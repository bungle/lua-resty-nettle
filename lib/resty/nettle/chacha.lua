require "resty.nettle.types.chacha"

local lib          = require "resty.nettle.library"
local ffi          = require "ffi"
local ffi_new      = ffi.new
local ffi_typeof   = ffi.typeof
local ffi_cdef     = ffi.cdef
local ffi_copy     = ffi.copy
local ffi_str      = ffi.string
local setmetatable = setmetatable

ffi_cdef[[
void nettle_chacha_set_key(struct chacha_ctx *ctx, const uint8_t *key);
void nettle_chacha_set_nonce(struct chacha_ctx *ctx, const uint8_t *nonce);
void nettle_chacha_crypt(struct chacha_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src);
]]

local uint8t = ffi_typeof "uint8_t[?]"

local chacha = {}
chacha.__index = chacha

local context  = ffi_typeof "CHACHA_CTX[1]"
local setkey   = lib.nettle_chacha_set_key
local setnonce = lib.nettle_chacha_set_nonce
local crypt    = lib.nettle_chacha_crypt

function chacha.new(key, nonce)
    local kl = #key
    if kl ~= 32 then
        return nil, "The ChaCha supported key size is 256 bits."
    end
    local nl = #nonce
    if nl ~= 8 then
        return nil, "The ChaCha supported nonce size is 64 bits."
    end
    local ct = ffi_new(context)
    setkey(ct, key)
    setnonce(ct, nonce)
    return setmetatable({ context = ct }, chacha)
end

function chacha:encrypt(src, len)
    len = len or #src
    local dst = ffi_new(uint8t, len)
    ffi_copy(dst, src, len)
    crypt(self.context, len, dst, dst)
    return ffi_str(dst, len)
end

function chacha:decrypt(src, len)
    len = len or #src
    local dst = ffi_new(uint8t, len)
    crypt(self.context, len, dst, src)
    return ffi_str(dst, len)
end

return chacha
