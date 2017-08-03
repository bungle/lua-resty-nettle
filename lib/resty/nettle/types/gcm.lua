require "resty.nettle.library"

local ffi      = require "ffi"
local ffi_cdef = ffi.cdef

ffi_cdef[[
typedef struct gcm_key {
  union nettle_block16 h[256];
} NETTLE_GCM_KEY;
typedef struct gcm_ctx {
  union nettle_block16 iv;
  union nettle_block16 ctr;
  union nettle_block16 x;
  uint64_t auth_size;
  uint64_t data_size;
} NETTLE_GCM_CTX;
void nettle_gcm_set_key(struct gcm_key *key, const void *cipher, nettle_cipher_func *f);
void nettle_gcm_set_iv(struct gcm_ctx *ctx, const struct gcm_key *key, size_t length, const uint8_t *iv);
void nettle_gcm_update(struct gcm_ctx *ctx, const struct gcm_key *key, size_t length, const uint8_t *data);
void nettle_gcm_encrypt(struct gcm_ctx *ctx, const struct gcm_key *key, const void *cipher, nettle_cipher_func *f, size_t length, uint8_t *dst, const uint8_t *src);
void nettle_gcm_decrypt(struct gcm_ctx *ctx, const struct gcm_key *key, const void *cipher, nettle_cipher_func *f, size_t length, uint8_t *dst, const uint8_t *src);
void nettle_gcm_digest(struct gcm_ctx *ctx, const struct gcm_key *key, const void *cipher, nettle_cipher_func *f, size_t length, uint8_t *digest);
]]
