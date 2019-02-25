local ffi = require "ffi"
local ffi_cdef = ffi.cdef
local ffi_typeof = ffi.typeof

ffi_cdef [[
void
nettle_chacha_set_key(struct chacha_ctx *ctx, const uint8_t *key);

void
nettle_chacha_set_nonce(struct chacha_ctx *ctx, const uint8_t *nonce);

void
nettle_chacha_set_nonce96(struct chacha_ctx *ctx, const uint8_t *nonce);

void
nettle_chacha_crypt(struct chacha_ctx *ctx, size_t length,
                    uint8_t *dst, const uint8_t *src);
]]

return ffi_typeof [[
struct chacha_ctx {
  uint32_t state[16];
}]]
