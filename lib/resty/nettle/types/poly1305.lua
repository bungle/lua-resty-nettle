require "resty.nettle.types.aes"

local ffi = require "ffi"
local ffi_cdef = ffi.cdef
local ffi_typeof = ffi.typeof

ffi_cdef [[
void nettle_poly1305_set_key(struct poly1305_ctx *ctx, const uint8_t key[16]);
void nettle_poly1305_digest(struct poly1305_ctx *ctx, union nettle_block16 *s);

void
nettle_poly1305_aes_set_key(struct poly1305_aes_ctx *ctx, const uint8_t *key);

void
nettle_poly1305_aes_set_nonce(struct poly1305_aes_ctx *ctx,
                              const uint8_t *nonce);

void
nettle_poly1305_aes_update(struct poly1305_aes_ctx *ctx, size_t length, const uint8_t *data);

void
nettle_poly1305_aes_digest(struct poly1305_aes_ctx *ctx,
                           size_t length, uint8_t *digest);
]]

return {
  poly1395 = ffi_typeof [[
struct poly1305_ctx {
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
}]],
  poly1395_aes = ffi_typeof [[
struct poly1305_aes_ctx {
  struct poly1305_ctx pctx;
  uint8_t block[16];
  unsigned index;
  uint8_t nonce[16];
  struct aes128_ctx aes;
}]]
}
