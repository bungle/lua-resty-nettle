require "resty.nettle.types.cipher"
require "resty.nettle.types.hash"
local ffi      = require "ffi"
local ffi_cdef = ffi.cdef

ffi_cdef[[
typedef void nettle_crypt_func(void *ctx, size_t length, uint8_t *dst, const uint8_t *src);
struct nettle_aead {
  const char *name;
  unsigned context_size;
  unsigned block_size;
  unsigned key_size;
  unsigned nonce_size;
  unsigned digest_size;
  nettle_set_key_func *set_encrypt_key;
  nettle_set_key_func *set_decrypt_key;
  nettle_set_key_func *set_nonce;
  nettle_hash_update_func *update;
  nettle_crypt_func *encrypt;
  nettle_crypt_func *decrypt;
  nettle_hash_digest_func *digest;
};
extern const struct nettle_aead * const nettle_aeads[];
]]