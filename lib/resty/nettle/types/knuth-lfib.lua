local ffi = require "ffi"
local ffi_cdef = ffi.cdef
local ffi_typeof = ffi.typeof

ffi_cdef [[
void
nettle_knuth_lfib_init(struct knuth_lfib_ctx *ctx, uint32_t seed);

uint32_t
nettle_knuth_lfib_get(struct knuth_lfib_ctx *ctx);

void
nettle_knuth_lfib_get_array(struct knuth_lfib_ctx *ctx,
                            size_t n, uint32_t *a);

void
nettle_knuth_lfib_random(struct knuth_lfib_ctx *ctx,
                         size_t n, uint8_t *dst);
]]

return ffi_typeof [[
struct knuth_lfib_ctx {
  uint32_t x[100];
  unsigned index;
}]]
