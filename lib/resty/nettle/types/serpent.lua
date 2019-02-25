local ffi = require "ffi"
local ffi_cdef = ffi.cdef
local ffi_typeof = ffi.typeof

ffi_cdef [[
void
nettle_serpent_set_key(struct serpent_ctx *ctx,
                       size_t length, const uint8_t *key);

void
nettle_serpent128_set_key(struct serpent_ctx *ctx, const uint8_t *key);

void
nettle_serpent192_set_key(struct serpent_ctx *ctx, const uint8_t *key);

void
nettle_serpent256_set_key(struct serpent_ctx *ctx, const uint8_t *key);

void
nettle_serpent_encrypt(const struct serpent_ctx *ctx,
                       size_t length, uint8_t *dst,
                       const uint8_t *src);

void
nettle_serpent_decrypt(const struct serpent_ctx *ctx,
                       size_t length, uint8_t *dst,
                       const uint8_t *src);
]]

return ffi_typeof [[
struct serpent_ctx {
  uint32_t keys[33][4];
}]]
