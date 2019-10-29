local ffi = require "ffi"
local ffi_cdef = ffi.cdef
local ffi_typeof = ffi.typeof

ffi_cdef [[
void
nettle_camellia128_set_encrypt_key(struct camellia128_ctx *ctx,
                                   const uint8_t *key);

void
nettle_camellia128_set_decrypt_key(struct camellia128_ctx *ctx,
                                   const uint8_t *key);

void
nettle_camellia128_invert_key(struct camellia128_ctx *dst,
                              const struct camellia128_ctx *src);

void
nettle_camellia128_crypt(const struct camellia128_ctx *ctx,
                         size_t length, uint8_t *dst,
                         const uint8_t *src);

void
nettle_camellia256_set_encrypt_key(struct camellia256_ctx *ctx,
                                   const uint8_t *key);

void
nettle_camellia256_set_decrypt_key(struct camellia256_ctx *ctx,
                                   const uint8_t *key);

void
nettle_camellia256_invert_key(struct camellia256_ctx *dst,
                              const struct camellia256_ctx *src);

void
nettle_camellia256_crypt(const struct camellia256_ctx *ctx,
                         size_t length, uint8_t *dst,
                         const uint8_t *src);

void
nettle_camellia192_set_encrypt_key(struct camellia256_ctx *ctx,
                                   const uint8_t *key);

void
nettle_camellia192_set_decrypt_key(struct camellia256_ctx *ctx,
                                   const uint8_t *key);
]]

local contexts = {
  camellia128 = ffi_typeof [[
struct camellia128_ctx {
  uint64_t keys[24];
}]],
  camellia256 = ffi_typeof [[
struct camellia256_ctx {
  uint64_t keys[32];
}]],
}

contexts.camellia192 = contexts.camellia256

return contexts
