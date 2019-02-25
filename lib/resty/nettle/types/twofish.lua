local ffi = require "ffi"
local ffi_cdef = ffi.cdef
local ffi_typeof = ffi.typeof

ffi_cdef [[
void
nettle_twofish_set_key(struct twofish_ctx *ctx,
                       size_t length, const uint8_t *key);

void
nettle_twofish128_set_key(struct twofish_ctx *context, const uint8_t *key);

void
nettle_twofish192_set_key(struct twofish_ctx *context, const uint8_t *key);

void
nettle_twofish256_set_key(struct twofish_ctx *context, const uint8_t *key);

void
nettle_twofish_encrypt(const struct twofish_ctx *ctx,
                       size_t length, uint8_t *dst,
                       const uint8_t *src);

void
nettle_twofish_decrypt(const struct twofish_ctx *ctx,
                       size_t length, uint8_t *dst,
                       const uint8_t *src);
]]

return ffi_typeof [[
struct twofish_ctx {
  uint32_t keys[40];
  uint32_t s_box[4][256];
}]]
