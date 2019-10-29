local ffi = require "ffi"
local ffi_cdef = ffi.cdef
local ffi_typeof = ffi.typeof

ffi_cdef [[
void
nettle_sha1_init(struct sha1_ctx *ctx);

void
nettle_sha1_update(struct sha1_ctx *ctx,
                   size_t length,
                   const uint8_t *data);

void
nettle_sha1_digest(struct sha1_ctx *ctx,
                   size_t length,
                   uint8_t *digest);
]]

return ffi_typeof [[
struct sha1_ctx {
  uint32_t state[5];
  uint64_t count;
  unsigned int index;
  uint8_t block[64];
}]]
