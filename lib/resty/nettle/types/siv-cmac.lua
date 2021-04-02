require "resty.nettle.types.aes"
require "resty.nettle.types.cmac"

local ffi = require "ffi"
local ffi_cdef = ffi.cdef
local ffi_typeof = ffi.typeof

ffi_cdef [[
void
nettle_siv_cmac_aes128_set_key(struct siv_cmac_aes128_ctx *ctx, const uint8_t *key);

void
nettle_siv_cmac_aes128_encrypt_message(const struct siv_cmac_aes128_ctx *ctx,
                                       size_t nlength, const uint8_t *nonce,
                                       size_t alength, const uint8_t *adata,
                                       size_t clength, uint8_t *dst, const uint8_t *src);

int
nettle_siv_cmac_aes128_decrypt_message(const struct siv_cmac_aes128_ctx *ctx,
                                       size_t nlength, const uint8_t *nonce,
                                       size_t alength, const uint8_t *adata,
                                       size_t mlength, uint8_t *dst, const uint8_t *src);

void
nettle_siv_cmac_aes256_set_key(struct siv_cmac_aes256_ctx *ctx, const uint8_t *key);

void
nettle_siv_cmac_aes256_encrypt_message(const struct siv_cmac_aes256_ctx *ctx,
                                       size_t nlength, const uint8_t *nonce,
                                       size_t alength, const uint8_t *adata,
                                       size_t clength, uint8_t *dst, const uint8_t *src);

int
nettle_siv_cmac_aes256_decrypt_message(const struct siv_cmac_aes256_ctx *ctx,
                                       size_t nlength, const uint8_t *nonce,
                                       size_t alength, const uint8_t *adata,
                                       size_t mlength, uint8_t *dst, const uint8_t *src);
]]

return {
  aes128 = ffi_typeof [[
struct siv_cmac_aes128_ctx {
  struct cmac128_key cmac_key;
  struct aes128_ctx cmac_cipher;
  struct aes128_ctx ctr_cipher;
}]],
  aes256 = ffi_typeof [[
struct siv_cmac_aes256_ctx {
  struct cmac128_key cmac_key;
  struct aes256_ctx cmac_cipher;
  struct aes256_ctx ctr_cipher;
}]]
}
