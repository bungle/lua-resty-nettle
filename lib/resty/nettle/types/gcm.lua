require "resty.nettle.types.nettle-types"
require "resty.nettle.types.aes"
require "resty.nettle.types.camellia"

local ffi = require "ffi"
local ffi_cdef = ffi.cdef
local ffi_typeof = ffi.typeof

ffi_cdef [[
void
nettle_gcm_set_key(struct gcm_key *key,
                   const void *cipher, nettle_cipher_func *f);

void
nettle_gcm_set_iv(struct gcm_ctx *ctx, const struct gcm_key *key,
                  size_t length, const uint8_t *iv);

void
nettle_gcm_update(struct gcm_ctx *ctx, const struct gcm_key *key,
                  size_t length, const uint8_t *data);

void
nettle_gcm_encrypt(struct gcm_ctx *ctx, const struct gcm_key *key,
                   const void *cipher, nettle_cipher_func *f,
                   size_t length, uint8_t *dst, const uint8_t *src);

void
nettle_gcm_decrypt(struct gcm_ctx *ctx, const struct gcm_key *key,
                   const void *cipher, nettle_cipher_func *f,
                   size_t length, uint8_t *dst, const uint8_t *src);

void
nettle_gcm_digest(struct gcm_ctx *ctx, const struct gcm_key *key,
                  const void *cipher, nettle_cipher_func *f,
                  size_t length, uint8_t *digest);

void
nettle_gcm_aes128_set_key(struct gcm_aes128_ctx *ctx, const uint8_t *key);

void
nettle_gcm_aes128_update(struct gcm_aes128_ctx *ctx,
                         size_t length, const uint8_t *data);
void
nettle_gcm_aes128_set_iv(struct gcm_aes128_ctx *ctx,
                         size_t length, const uint8_t *iv);

void
nettle_gcm_aes128_encrypt(struct gcm_aes128_ctx *ctx,
                          size_t length, uint8_t *dst, const uint8_t *src);

void
nettle_gcm_aes128_decrypt(struct gcm_aes128_ctx *ctx,
                          size_t length, uint8_t *dst, const uint8_t *src);

void
nettle_gcm_aes128_digest(struct gcm_aes128_ctx *ctx,
                         size_t length, uint8_t *digest);

void
nettle_gcm_aes192_set_key(struct gcm_aes192_ctx *ctx, const uint8_t *key);

void
nettle_gcm_aes192_update(struct gcm_aes192_ctx *ctx,
                         size_t length, const uint8_t *data);

void
nettle_gcm_aes192_set_iv(struct gcm_aes192_ctx *ctx,
                        size_t length, const uint8_t *iv);

void
nettle_gcm_aes192_encrypt(struct gcm_aes192_ctx *ctx,
                          size_t length, uint8_t *dst, const uint8_t *src);

void
nettle_gcm_aes192_decrypt(struct gcm_aes192_ctx *ctx,
                          size_t length, uint8_t *dst, const uint8_t *src);

void
nettle_gcm_aes192_digest(struct gcm_aes192_ctx *ctx,
                         size_t length, uint8_t *digest);

void
nettle_gcm_aes256_set_key(struct gcm_aes256_ctx *ctx, const uint8_t *key);

void
nettle_gcm_aes256_update(struct gcm_aes256_ctx *ctx,
                         size_t length, const uint8_t *data);

void
nettle_gcm_aes256_set_iv(struct gcm_aes256_ctx *ctx,
                         size_t length, const uint8_t *iv);

void
nettle_gcm_aes256_encrypt(struct gcm_aes256_ctx *ctx,
                          size_t length, uint8_t *dst, const uint8_t *src);

void
nettle_gcm_aes256_decrypt(struct gcm_aes256_ctx *ctx,
                          size_t length, uint8_t *dst, const uint8_t *src);

void
nettle_gcm_aes256_digest(struct gcm_aes256_ctx *ctx,
                         size_t length, uint8_t *digest);

void
nettle_gcm_camellia128_set_key(struct gcm_camellia128_ctx *ctx,
                               const uint8_t *key);

void
nettle_gcm_camellia128_set_iv(struct gcm_camellia128_ctx *ctx,
                              size_t length, const uint8_t *iv);

void
nettle_gcm_camellia128_update(struct gcm_camellia128_ctx *ctx,
                              size_t length, const uint8_t *data);

void
nettle_gcm_camellia128_encrypt(struct gcm_camellia128_ctx *ctx,
                               size_t length, uint8_t *dst, const uint8_t *src);

void
nettle_gcm_camellia128_decrypt(struct gcm_camellia128_ctx *ctx,
                               size_t length, uint8_t *dst, const uint8_t *src);

void
nettle_gcm_camellia128_digest(struct gcm_camellia128_ctx *ctx,
                              size_t length, uint8_t *digest);

void
nettle_gcm_camellia256_set_key(struct gcm_camellia256_ctx *ctx,
                               const uint8_t *key);

void
nettle_gcm_camellia256_set_iv(struct gcm_camellia256_ctx *ctx,
                              size_t length, const uint8_t *iv);

void
nettle_gcm_camellia256_update(struct gcm_camellia256_ctx *ctx,
                              size_t length, const uint8_t *data);

void
nettle_gcm_camellia256_encrypt(struct gcm_camellia256_ctx *ctx,
                               size_t length, uint8_t *dst, const uint8_t *src);

void
nettle_gcm_camellia256_decrypt(struct gcm_camellia256_ctx *ctx,
                               size_t length, uint8_t *dst, const uint8_t *src);

void
nettle_gcm_camellia256_digest(struct gcm_camellia256_ctx *ctx,
                              size_t length, uint8_t *digest);
]]

return {
  key = ffi_typeof [[
struct gcm_key {
  union nettle_block16 h[1 << 8];
}]],
  gcm = ffi_typeof [[
struct gcm_ctx {
  union nettle_block16 iv;
  union nettle_block16 ctr;
  union nettle_block16 x;
  uint64_t auth_size;
  uint64_t data_size;
}]],
  gcm_aes128 = ffi_typeof [[
struct gcm_aes128_ctx {
  struct gcm_key key;
  struct gcm_ctx gcm;
  struct aes128_ctx cipher;
}]],
  gcm_aes192 = ffi_typeof [[
struct gcm_aes192_ctx {
  struct gcm_key key;
  struct gcm_ctx gcm;
  struct aes192_ctx cipher;
}]],
  gcm_aes256 = ffi_typeof [[
struct gcm_aes256_ctx {
  struct gcm_key key;
  struct gcm_ctx gcm;
  struct aes256_ctx cipher;
}]],
  gcm_camellia128 = ffi_typeof [[
struct gcm_camellia128_ctx {
  struct gcm_key key;
  struct gcm_ctx gcm;
  struct camellia128_ctx cipher;
}]],
  gcm_camellia256 = ffi_typeof [[
struct gcm_camellia256_ctx {
  struct gcm_key key;
  struct gcm_ctx gcm;
  struct camellia256_ctx cipher;
}]],
}
