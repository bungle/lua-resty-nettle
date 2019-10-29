local ffi = require "ffi"
local ffi_cdef = ffi.cdef
local ffi_typeof = ffi.typeof

ffi_cdef [[
void
nettle_arcfour_set_key(struct arcfour_ctx *ctx,
                size_t length, const uint8_t *key);

void
nettle_arcfour128_set_key(struct arcfour_ctx *ctx, const uint8_t *key);

void
nettle_arcfour_crypt(struct arcfour_ctx *ctx,
                     size_t length, uint8_t *dst,
                     const uint8_t *src);
]]

return ffi_typeof [[
struct arcfour_ctx {
  uint8_t S[256];
  uint8_t i;
  uint8_t j;
}]]
