local ffi      = require "ffi"
local ffi_cdef = ffi.cdef

ffi_cdef[[
typedef void nettle_set_key_func(void *ctx, const uint8_t *key);
typedef void nettle_cipher_func(const void *ctx, size_t length, uint8_t *dst, const uint8_t *src);
struct nettle_cipher {
  const char *name;
  unsigned context_size;
  unsigned block_size;
  unsigned key_size;
  nettle_set_key_func *set_encrypt_key;
  nettle_set_key_func *set_decrypt_key;
  nettle_cipher_func *encrypt;
  nettle_cipher_func *decrypt;
};
extern const struct nettle_cipher * const nettle_ciphers[];
]]