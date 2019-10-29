local ffi = require "ffi"
local ffi_cdef = ffi.cdef
local ffi_typeof = ffi.typeof

ffi_cdef [[
void
nettle_md4_init(struct md4_ctx *ctx);

void
nettle_md4_update(struct md4_ctx *ctx,
                  size_t length,
                  const uint8_t *data);

void
nettle_md4_digest(struct md4_ctx *ctx,
                  size_t length,
                  uint8_t *digest);
]]

return ffi_typeof [[
struct md4_ctx {
  uint32_t state[4];
  uint64_t count;
  unsigned index;
  uint8_t block[64];
}]]
