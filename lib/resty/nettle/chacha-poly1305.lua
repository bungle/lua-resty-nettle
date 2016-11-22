require "resty.nettle.types.chacha"
require "resty.nettle.types.poly1305"

local lib          = require "resty.nettle.library"
local ffi          = require "ffi"
local ffi_new      = ffi.new
local ffi_typeof   = ffi.typeof
local ffi_cdef     = ffi.cdef
local ffi_str      = ffi.string
local assert       = assert
local setmetatable = setmetatable

ffi_cdef[[
typedef struct chacha_poly1305_ctx {
  struct chacha_ctx chacha;
  struct poly1305_ctx poly1305;
  union nettle_block16 s;
  uint64_t auth_size;
  uint64_t data_size;
  uint8_t block[16];
  unsigned index;
} CHACHA_POLY1305;
void nettle_chacha_poly1305_set_key(struct chacha_poly1305_ctx *ctx, const uint8_t *key);
void nettle_chacha_poly1305_set_nonce(struct chacha_poly1305_ctx *ctx, const uint8_t *nonce);
void nettle_chacha_poly1305_update(struct chacha_poly1305_ctx *ctx, size_t length, const uint8_t *data);
void nettle_chacha_poly1305_encrypt(struct chacha_poly1305_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src);
void nettle_chacha_poly1305_decrypt(struct chacha_poly1305_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src);
void nettle_chacha_poly1305_digest(struct chacha_poly1305_ctx *ctx, size_t length, uint8_t *digest);
]]

local uint8t = ffi_typeof "uint8_t[?]"
local dgt    = ffi_new(uint8t, 16)

local chacha_poly1305 = {}
chacha_poly1305.__index = chacha_poly1305

local context  = ffi_typeof "CHACHA_POLY1305[1]"
local setkey   = lib.nettle_chacha_poly1305_set_key
local setnonce = lib.nettle_chacha_poly1305_set_nonce
local update   = lib.nettle_chacha_poly1305_update
local encrypt  = lib.nettle_chacha_poly1305_encrypt
local decrypt  = lib.nettle_chacha_poly1305_decrypt
local digest   = lib.nettle_chacha_poly1305_digest

function chacha_poly1305.new(key, nonce, ad)
    local kl = #key
    assert(kl == 32, "The ChaCha-Poly1305 supported key size is 256 bits.")
    local nl = #nonce
    assert(nl == 16, "The ChaCha-Poly1305 supported nonce size is 128 bits.")
    local ct = ffi_new(context)
    setkey(ct, key)
    setnonce(ct, nonce)
    if ad then
        update(ct, #ad, ad)
    end
    return setmetatable({ context = ct }, chacha_poly1305)
end

function chacha_poly1305:encrypt(src)
    local len = #src
    local ctx = self.context
    local dst = ffi_new(uint8t, len)
    encrypt(ctx, len, dst, src)
    digest(ctx, 16, dgt)
    return ffi_str(dst, len), ffi_str(dgt, 16)
end

function chacha_poly1305:decrypt(src)
    local len = #src
    local ctx = self.context
    local dst = ffi_new(uint8t, len)
    decrypt(ctx, len, dst, src)
    digest(ctx, 16, dgt)
    return ffi_str(dst, len), ffi_str(dgt, 16)
end

return chacha_poly1305
