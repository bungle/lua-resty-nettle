local ffi = require "ffi"
local ffi_cdef = ffi.cdef
local ffi_typeof = ffi.typeof

ffi_cdef [[
void
nettle_gosthash94_init(struct gosthash94_ctx *ctx);

void
nettle_gosthash94_update(struct gosthash94_ctx *ctx,
		                 size_t length, const uint8_t *msg);
void
nettle_gosthash94_digest(struct gosthash94_ctx *ctx,
                         size_t length, uint8_t *result);
]]

return ffi_typeof [[
struct gosthash94_ctx {
  uint32_t hash[8];
  uint32_t sum[8];
  uint64_t length;
  uint8_t message[32];
}]]
