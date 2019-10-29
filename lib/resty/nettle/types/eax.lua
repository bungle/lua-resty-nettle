require "resty.nettle.types.nettle-types"

local ffi = require "ffi"
local ffi_cdef = ffi.cdef
local ffi_typeof = ffi.typeof

ffi_cdef [[
struct eax_key {
  union nettle_block16 pad_block;
  union nettle_block16 pad_partial;
};

void
nettle_eax_set_key(struct eax_key *key, const void *cipher, nettle_cipher_func *f);

void
nettle_eax_set_nonce(struct eax_ctx *eax, const struct eax_key *key,
                     const void *cipher, nettle_cipher_func *f,
                     size_t nonce_length, const uint8_t *nonce);

void
nettle_eax_update(struct eax_ctx *eax, const struct eax_key *key,
                  const void *cipher, nettle_cipher_func *f,
                  size_t data_length, const uint8_t *data);

void
nettle_eax_encrypt(struct eax_ctx *eax, const struct eax_key *key,
                   const void *cipher, nettle_cipher_func *f,
                   size_t length, uint8_t *dst, const uint8_t *src);

void
nettle_eax_decrypt(struct eax_ctx *eax, const struct eax_key *key,
                   const void *cipher, nettle_cipher_func *f,
                   size_t length, uint8_t *dst, const uint8_t *src);

void
nettle_eax_digest(struct eax_ctx *eax, const struct eax_key *key,
                  const void *cipher, nettle_cipher_func *f,
                  size_t length, uint8_t *digest);

void
nettle_eax_aes128_set_key(struct eax_aes128_ctx *ctx, const uint8_t *key);

void
nettle_eax_aes128_set_nonce(struct eax_aes128_ctx *ctx,
                            size_t length, const uint8_t *iv);

void
nettle_eax_aes128_update(struct eax_aes128_ctx *ctx,
                         size_t length, const uint8_t *data);

void
nettle_eax_aes128_encrypt(struct eax_aes128_ctx *ctx,
                          size_t length, uint8_t *dst, const uint8_t *src);

void
nettle_eax_aes128_decrypt(struct eax_aes128_ctx *ctx,
                          size_t length, uint8_t *dst, const uint8_t *src);

void
nettle_eax_aes128_digest(struct eax_aes128_ctx *ctx, size_t length, uint8_t *digest);
]]

return {
  eax = ffi_typeof [[
struct eax_ctx {
  union nettle_block16 omac_nonce;
  union nettle_block16 omac_data;
  union nettle_block16 omac_message;
  union nettle_block16 ctr;
}]],
  eax_aes128 = ffi_typeof [[
struct eax_aes128_ctx {
  struct eax_key key;
  struct eax_ctx eax;
  struct aes128_ctx cipher;
}]],
}
