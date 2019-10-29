local ffi = require "ffi"
local ffi_cdef = ffi.cdef
local ffi_typeof = ffi.typeof

ffi_cdef [[
void
nettle_ripemd160_init(struct ripemd160_ctx *ctx);

void
nettle_ripemd160_update(struct ripemd160_ctx *ctx,
                        size_t length,
                        const uint8_t *data);

void
nettle_ripemd160_digest(struct ripemd160_ctx *ctx,
                        size_t length,
                        uint8_t *digest);
]]

return ffi_typeof [[
struct ripemd160_ctx {
  uint32_t state[5];
  uint64_t count;
  unsigned int index;
  uint8_t block[64];
}]]
