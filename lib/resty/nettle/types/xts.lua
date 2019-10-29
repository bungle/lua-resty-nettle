local ffi = require "ffi"
local ffi_cdef = ffi.cdef
local ffi_typeof = ffi.typeof

ffi_cdef [[
void
nettle_xts_encrypt_message(const void *enc_ctx, const void *twk_ctx,
                nettle_cipher_func *encf,
                const uint8_t *tweak, size_t length,
                uint8_t *dst, const uint8_t *src);
void
nettle_xts_decrypt_message(const void *dec_ctx, const void *twk_ctx,
                    nettle_cipher_func *decf, nettle_cipher_func *encf,
                    const uint8_t *tweak, size_t length,
                    uint8_t *dst, const uint8_t *src);

void
nettle_xts_aes128_set_encrypt_key(struct xts_aes128_key *xts_key,
                           const uint8_t *key);

void
nettle_xts_aes128_set_decrypt_key(struct xts_aes128_key *xts_key,
                           const uint8_t *key);

void
nettle_xts_aes128_encrypt_message(struct xts_aes128_key *xtskey,
                           const uint8_t *tweak, size_t length,
                           uint8_t *dst, const uint8_t *src);

void
nettle_xts_aes128_decrypt_message(struct xts_aes128_key *xts_key,
                           const uint8_t *tweak, size_t length,
                           uint8_t *dst, const uint8_t *src);

void
nettle_xts_aes256_set_encrypt_key(struct xts_aes256_key *xts_key,
                           const uint8_t *key);

void
nettle_xts_aes256_set_decrypt_key(struct xts_aes256_key *xts_key,
                           const uint8_t *key);

void
nettle_xts_aes256_encrypt_message(struct xts_aes256_key *xts_key,
                           const uint8_t *tweak, size_t length,
                           uint8_t *dst, const uint8_t *src);

void
nettle_xts_aes256_decrypt_message(struct xts_aes256_key *xts_key,
                           const uint8_t *tweak, size_t length,
                           uint8_t *dst, const uint8_t *src);
]]


return {
  aes128_key = ffi_typeof [[
struct xts_aes128_key {
    struct aes128_ctx cipher;
    struct aes128_ctx tweak_cipher;
};]],
  aes256_key = ffi_typeof [[
struct xts_aes256_key {
    struct aes256_ctx cipher;
    struct aes256_ctx tweak_cipher;
};]]
}
