require "resty.nettle.types.aes"

local ffi        = require "ffi"
local ffi_new    = ffi.new
local ffi_typeof = ffi.typeof
local ffi_cdef   = ffi.cdef
local ffi_str    = ffi.string
local nettle     = require "resty.nettle"

ffi_cdef[[
typedef struct poly1305_ctx {
  union {
    uint32_t r32[6];
    uint64_t r64[3];
  } r;
  uint32_t s32[3];
  uint32_t hh;
  union {
    uint32_t h32[4];
    uint64_t h64[2];
  } h;
} POLY1305_CTX;
typedef struct poly1305_aes_ctx {
  struct poly1305_ctx pctx;
  uint8_t block[16];
  unsigned index;
  uint8_t nonce[16];
  struct aes128_ctx aes;
} POLY1305_AES_CTX;
void nettle_poly1305_aes_set_key(struct poly1305_aes_ctx *ctx, const uint8_t *key);
void nettle_poly1305_aes_set_nonce(struct poly1305_aes_ctx *ctx, const uint8_t *nonce);
void nettle_poly1305_aes_update(struct poly1305_aes_ctx *ctx, size_t length, const uint8_t *data);
void nettle_poly1305_aes_digest(struct poly1305_aes_ctx *ctx, size_t length, uint8_t *digest);
]]

local ctxply = ffi_typeof("POLY1305_AES_CTX[1]")
local buf128 = ffi_new("uint8_t[?]", 16)

local poly1305 = {}
poly1305.__index = poly1305

function poly1305.new(key, nonce)
    local self = setmetatable({ context = ffi_new(ctxply) }, poly1305)
    nettle.nettle_poly1305_aes_set_key(self.context, key)
    if nonce then
        nettle.nettle_poly1305_aes_set_nonce(self.context, #nonce, nonce)
    end
    return self
end

function poly1305:update(data)
    return nettle.nettle_poly1305_aes_update(self.context, #data, data)
end

function poly1305:digest()
    nettle.nettle_poly1305_aes_digest(self.context, 16, buf128)
    return ffi_str(buf128, 16)
end

return poly1305