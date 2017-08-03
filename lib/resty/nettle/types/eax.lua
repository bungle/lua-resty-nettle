require "resty.nettle.library"

local ffi      = require "ffi"
local ffi_cdef = ffi.cdef

ffi_cdef[[
typedef struct eax_key {
  union nettle_block16 pad_block;
  union nettle_block16 pad_partial;
} NETTLE_EAX_KEY;
typedef struct eax_ctx {
  union nettle_block16 omac_nonce;
  union nettle_block16 omac_data;
  union nettle_block16 omac_message;
  union nettle_block16 ctr;
} NETTLE_EAX_CTX;
void nettle_eax_set_key (struct eax_key *key, const void *cipher, nettle_cipher_func *f);
void nettle_eax_set_nonce (struct eax_ctx *eax, const struct eax_key *key, const void *cipher, nettle_cipher_func *f, size_t nonce_length, const uint8_t *nonce);
void nettle_eax_update (struct eax_ctx *eax, const struct eax_key *key, const void *cipher, nettle_cipher_func *f, size_t data_length, const uint8_t *data);
void nettle_eax_encrypt (struct eax_ctx *eax, const struct eax_key *key, const void *cipher, nettle_cipher_func *f, size_t length, uint8_t *dst, const uint8_t *src);
void nettle_eax_decrypt (struct eax_ctx *eax, const struct eax_key *key, const void *cipher, nettle_cipher_func *f, size_t length, uint8_t *dst, const uint8_t *src);
void nettle_eax_digest (struct eax_ctx *eax, const struct eax_key *key, const void *cipher, nettle_cipher_func *f, size_t length, uint8_t *digest);
]]
