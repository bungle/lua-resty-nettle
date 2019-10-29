local ffi = require "ffi"
local ffi_cdef = ffi.cdef
local ffi_typeof = ffi.typeof

ffi_cdef [[
int
nettle_blowfish_set_key(struct blowfish_ctx *ctx,
                        size_t length, const uint8_t *key);
int
nettle_blowfish128_set_key(struct blowfish_ctx *ctx, const uint8_t *key);

void
nettle_blowfish_encrypt(const struct blowfish_ctx *ctx,
                        size_t length, uint8_t *dst,
                        const uint8_t *src);
void
nettle_blowfish_decrypt(const struct blowfish_ctx *ctx,
                        size_t length, uint8_t *dst,
                        const uint8_t *src);
]]

return ffi_typeof [[
struct blowfish_ctx {
  uint32_t s[4][256];
  uint32_t p[18];
}]]
