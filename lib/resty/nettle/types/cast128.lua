local ffi = require "ffi"
local ffi_cdef = ffi.cdef
local ffi_typeof = ffi.typeof

ffi_cdef [[
void
nettle_cast5_set_key(struct cast128_ctx *ctx,
                     size_t length, const uint8_t *key);

void
nettle_cast128_set_key(struct cast128_ctx *ctx, const uint8_t *key);

void
nettle_cast128_encrypt(const struct cast128_ctx *ctx,
                       size_t length, uint8_t *dst,
                       const uint8_t *src);

void
nettle_cast128_decrypt(const struct cast128_ctx *ctx,
                       size_t length, uint8_t *dst,
                       const uint8_t *src);
]]

return ffi_typeof [[
struct cast128_ctx {
  unsigned rounds;
  unsigned char Kr[16];
  uint32_t Km[16];
}]]
