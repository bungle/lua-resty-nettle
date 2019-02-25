local ffi = require "ffi"
local ffi_cdef = ffi.cdef
local ffi_typeof = ffi.typeof

ffi_cdef [[
void
nettle_md2_init(struct md2_ctx *ctx);

void
nettle_md2_update(struct md2_ctx *ctx,
                  size_t length,
                  const uint8_t *data);

void
nettle_md2_digest(struct md2_ctx *ctx,
                  size_t length,
                  uint8_t *digest);
]]

return ffi_typeof [[
struct md2_ctx {
  uint8_t C[16];
  uint8_t X[3 * 16];
  unsigned index;
  uint8_t block[16];
}]]
