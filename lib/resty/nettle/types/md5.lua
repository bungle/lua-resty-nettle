local ffi = require "ffi"
local ffi_cdef = ffi.cdef
local ffi_typeof = ffi.typeof

ffi_cdef [[
void
nettle_md5_init(struct md5_ctx *ctx);

void
nettle_md5_update(struct md5_ctx *ctx,
                  size_t length,
                  const uint8_t *data);

void
nettle_md5_digest(struct md5_ctx *ctx,
                  size_t length,
                  uint8_t *digest);
]]

return ffi_typeof [[
struct md5_ctx {
  uint32_t state[16];
  uint64_t count;
  unsigned index;
  uint8_t block[64];
}]]
