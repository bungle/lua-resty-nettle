require "resty.nettle.types.chacha"
require "resty.nettle.types.poly1305"

local ffi = require "ffi"
local ffi_cdef = ffi.cdef
local ffi_typeof = ffi.typeof

ffi_cdef [[
void
nettle_chacha_poly1305_set_key(struct chacha_poly1305_ctx *ctx,
                               const uint8_t *key);

void
nettle_chacha_poly1305_set_nonce(struct chacha_poly1305_ctx *ctx,
                                 const uint8_t *nonce);

void
nettle_chacha_poly1305_update(struct chacha_poly1305_ctx *ctx,
                              size_t length, const uint8_t *data);

void
nettle_chacha_poly1305_encrypt(struct chacha_poly1305_ctx *ctx,
                               size_t length, uint8_t *dst, const uint8_t *src);

void
nettle_chacha_poly1305_decrypt(struct chacha_poly1305_ctx *ctx,
                               size_t length, uint8_t *dst, const uint8_t *src);

void
nettle_chacha_poly1305_digest(struct chacha_poly1305_ctx *ctx,
                              size_t length, uint8_t *digest);
]]

return ffi_typeof [[
struct chacha_poly1305_ctx {
  struct chacha_ctx chacha;
  struct poly1305_ctx poly1305;
  union nettle_block16 s;
  uint64_t auth_size;
  uint64_t data_size;
  uint8_t block[16];
  unsigned index;
}]]
