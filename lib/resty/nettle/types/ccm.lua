require "resty.nettle.types.nettle-types"

local ffi = require "ffi"
local ffi_cdef = ffi.cdef
local ffi_typeof = ffi.typeof

ffi_cdef [[
void
nettle_ccm_set_nonce(struct ccm_ctx *ctx, const void *cipher, nettle_cipher_func *f,
                     size_t noncelen, const uint8_t *nonce,
                     size_t authlen, size_t msglen, size_t taglen);

void
nettle_ccm_update(struct ccm_ctx *ctx, const void *cipher, nettle_cipher_func *f,
                  size_t length, const uint8_t *data);

void
nettle_ccm_encrypt(struct ccm_ctx *ctx, const void *cipher, nettle_cipher_func *f,
                   size_t length, uint8_t *dst, const uint8_t *src);

void
nettle_ccm_decrypt(struct ccm_ctx *ctx, const void *cipher, nettle_cipher_func *f,
                   size_t length, uint8_t *dst, const uint8_t *src);

void
nettle_ccm_digest(struct ccm_ctx *ctx, const void *cipher, nettle_cipher_func *f,
                  size_t length, uint8_t *digest);

void
nettle_ccm_encrypt_message(const void *cipher, nettle_cipher_func *f,
                           size_t nlength, const uint8_t *nonce,
                           size_t alength, const uint8_t *adata,
                           size_t tlength,
                           size_t clength, uint8_t *dst, const uint8_t *src);

int
nettle_ccm_decrypt_message(const void *cipher, nettle_cipher_func *f,
                           size_t nlength, const uint8_t *nonce,
                           size_t alength, const uint8_t *adata,
                           size_t tlength,
                           size_t mlength, uint8_t *dst, const uint8_t *src);

void
nettle_ccm_aes128_set_key(struct ccm_aes128_ctx *ctx, const uint8_t *key);

void
nettle_ccm_aes128_set_nonce(struct ccm_aes128_ctx *ctx,
                            size_t length, const uint8_t *nonce,
                            size_t authlen, size_t msglen, size_t taglen);

void
nettle_ccm_aes128_update(struct ccm_aes128_ctx *ctx,
                         size_t length, const uint8_t *data);

void
nettle_ccm_aes128_encrypt(struct ccm_aes128_ctx *ctx,
                          size_t length, uint8_t *dst, const uint8_t *src);

void
nettle_ccm_aes128_decrypt(struct ccm_aes128_ctx *ctx,
                          size_t length, uint8_t *dst, const uint8_t *src);

void
nettle_ccm_aes128_digest(struct ccm_aes128_ctx *ctx,
                         size_t length, uint8_t *digest);

void
nettle_ccm_aes128_encrypt_message(struct ccm_aes128_ctx *ctx,
                                  size_t nlength, const uint8_t *nonce,
                                  size_t alength, const uint8_t *adata,
                                  size_t tlength,
                                  size_t clength, uint8_t *dst, const uint8_t *src);

int
nettle_ccm_aes128_decrypt_message(struct ccm_aes128_ctx *ctx,
                                  size_t nlength, const uint8_t *nonce,
                                  size_t alength, const uint8_t *adata,
                                  size_t tlength,
                                  size_t mlength, uint8_t *dst, const uint8_t *src);


void
nettle_ccm_aes192_set_key(struct ccm_aes192_ctx *ctx, const uint8_t *key);

void
nettle_ccm_aes192_set_nonce(struct ccm_aes192_ctx *ctx,
                            size_t length, const uint8_t *nonce,
                            size_t authlen, size_t msglen, size_t taglen);

void
nettle_ccm_aes192_update(struct ccm_aes192_ctx *ctx,
                         size_t length, const uint8_t *data);

void
nettle_ccm_aes192_encrypt(struct ccm_aes192_ctx *ctx,
                          size_t length, uint8_t *dst, const uint8_t *src);

void
nettle_ccm_aes192_decrypt(struct ccm_aes192_ctx *ctx,
                          size_t length, uint8_t *dst, const uint8_t *src);

void
nettle_ccm_aes192_digest(struct ccm_aes192_ctx *ctx,
                         size_t length, uint8_t *digest);

void
nettle_ccm_aes192_encrypt_message(struct ccm_aes192_ctx *ctx,
                                  size_t nlength, const uint8_t *nonce,
                                  size_t alength, const uint8_t *adata,
                                  size_t tlength,
                                  size_t clength, uint8_t *dst, const uint8_t *src);

int
nettle_ccm_aes192_decrypt_message(struct ccm_aes192_ctx *ctx,
                                  size_t nlength, const uint8_t *nonce,
                                  size_t alength, const uint8_t *adata,
                                  size_t tlength,
                                  size_t mlength, uint8_t *dst, const uint8_t *src);

void
nettle_ccm_aes256_set_key(struct ccm_aes256_ctx *ctx, const uint8_t *key);

void
nettle_ccm_aes256_set_nonce(struct ccm_aes256_ctx *ctx,
                            size_t length, const uint8_t *nonce,
                            size_t authlen, size_t msglen, size_t taglen);

void
nettle_ccm_aes256_update(struct ccm_aes256_ctx *ctx,
                         size_t length, const uint8_t *data);

void
nettle_ccm_aes256_encrypt(struct ccm_aes256_ctx *ctx,
                          size_t length, uint8_t *dst, const uint8_t *src);

void
nettle_ccm_aes256_decrypt(struct ccm_aes256_ctx *ctx,
                          size_t length, uint8_t *dst, const uint8_t *src);

void
nettle_ccm_aes256_digest(struct ccm_aes256_ctx *ctx,
                         size_t length, uint8_t *digest);

void
nettle_ccm_aes256_encrypt_message(struct ccm_aes256_ctx *ctx,
                                  size_t nlength, const uint8_t *nonce,
                                  size_t alength, const uint8_t *adata,
                                  size_t tlength,
                                  size_t clength, uint8_t *dst, const uint8_t *src);

int
nettle_ccm_aes256_decrypt_message(struct ccm_aes256_ctx *ctx,
                                  size_t nlength, const uint8_t *nonce,
                                  size_t alength, const uint8_t *adata,
                                  size_t tlength,
                                  size_t mlength, uint8_t *dst, const uint8_t *src);
]]

return {
  ccm = ffi_typeof [[
struct ccm_ctx {
  union nettle_block16 ctr;
  union nettle_block16 tag;
  unsigned int blength;
}]],
  ccm_aes128 = ffi_typeof [[
struct ccm_aes128_ctx {
  struct ccm_ctx      ccm;
  struct aes128_ctx   cipher;
}]],
  ccm_aes192 = ffi_typeof [[
struct ccm_aes192_ctx {
  struct ccm_ctx      ccm;
  struct aes192_ctx   cipher;
}]],
  ccm_aes256 = ffi_typeof [[
struct ccm_aes256_ctx {
  struct ccm_ctx      ccm;
  struct aes256_ctx   cipher;
}]],
}
