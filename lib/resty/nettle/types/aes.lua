local ffi = require "ffi"
local ffi_cdef = ffi.cdef
local ffi_typeof = ffi.typeof

ffi_cdef [[
void
nettle_aes128_set_encrypt_key(struct aes128_ctx *ctx, const uint8_t *key);

void
nettle_aes128_set_decrypt_key(struct aes128_ctx *ctx, const uint8_t *key);

void
nettle_aes128_invert_key(struct aes128_ctx *dst,
                         const struct aes128_ctx *src);

void
nettle_aes128_encrypt(const struct aes128_ctx *ctx,
                      size_t length, uint8_t *dst,
                      const uint8_t *src);

void
nettle_aes128_decrypt(const struct aes128_ctx *ctx,
                      size_t length, uint8_t *dst,
                      const uint8_t *src);

void
nettle_aes192_set_encrypt_key(struct aes192_ctx *ctx, const uint8_t *key);

void
nettle_aes192_set_decrypt_key(struct aes192_ctx *ctx, const uint8_t *key);

void
nettle_aes192_invert_key(struct aes192_ctx *dst,
                         const struct aes192_ctx *src);

void
nettle_aes192_encrypt(const struct aes192_ctx *ctx,
                      size_t length, uint8_t *dst,
                      const uint8_t *src);

void
nettle_aes192_decrypt(const struct aes192_ctx *ctx,
                      size_t length, uint8_t *dst,
                      const uint8_t *src);

void
nettle_aes256_set_encrypt_key(struct aes256_ctx *ctx, const uint8_t *key);

void
nettle_aes256_set_decrypt_key(struct aes256_ctx *ctx, const uint8_t *key);

void
nettle_aes256_invert_key(struct aes256_ctx *dst,
                         const struct aes256_ctx *src);

void
nettle_aes256_encrypt(const struct aes256_ctx *ctx,
                      size_t length, uint8_t *dst,
                      const uint8_t *src);

void
nettle_aes256_decrypt(const struct aes256_ctx *ctx,
                      size_t length, uint8_t *dst,
                      const uint8_t *src);
]]

return {
  aes128 = ffi_typeof [[
struct aes128_ctx {
  uint32_t keys[4 * (10 + 1)];
}]],
  aes192 = ffi_typeof [[
struct aes192_ctx {
  uint32_t keys[4 * (12 + 1)];
}]],
  aes256 = ffi_typeof [[
struct aes256_ctx {
  uint32_t keys[4 * (14 + 1)];
}]],
}

