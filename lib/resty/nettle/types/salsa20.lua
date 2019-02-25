local ffi = require "ffi"
local ffi_cdef = ffi.cdef
local ffi_typeof = ffi.typeof

ffi_cdef [[
void
nettle_salsa20_128_set_key(struct salsa20_ctx *ctx, const uint8_t *key);

void
nettle_salsa20_256_set_key(struct salsa20_ctx *ctx, const uint8_t *key);

void
nettle_salsa20_set_key(struct salsa20_ctx *ctx,
                       size_t length, const uint8_t *key);

void
nettle_salsa20_set_nonce(struct salsa20_ctx *ctx, const uint8_t *nonce);

void
nettle_salsa20_crypt(struct salsa20_ctx *ctx,
                     size_t length, uint8_t *dst,
                     const uint8_t *src);

void
nettle_salsa20r12_crypt(struct salsa20_ctx *ctx,
                        size_t length, uint8_t *dst,
                        const uint8_t *src);
]]

return ffi_typeof [[
struct salsa20_ctx {
  uint32_t input[16];
}]]
