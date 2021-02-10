local ffi = require "ffi"
local ffi_cdef = ffi.cdef
local ffi_typeof = ffi.typeof

ffi_cdef [[
void
nettle_streebog512_init(struct streebog512_ctx *ctx);

void
nettle_streebog512_update(struct streebog512_ctx *ctx,
	                        size_t length,
	                        const uint8_t *data);

void
nettle_streebog512_digest(struct streebog512_ctx *ctx,
	                        size_t length,
	                        uint8_t *digest);

void
nettle_streebog256_init(struct streebog512_ctx *ctx);

void
nettle_streebog256_digest(struct streebog512_ctx *ctx,
		                      size_t length,
		                      uint8_t *digest);
]]


return ffi_typeof [[
struct streebog512_ctx {
  uint64_t state[8];
  uint64_t count[8];
  uint64_t sigma[8];
  unsigned int index;
  uint8_t block[64];
}]]
