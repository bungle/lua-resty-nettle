require "resty.nettle.types.aes"
require "resty.nettle.types.sha2"

local ffi = require "ffi"
local ffi_cdef = ffi.cdef
local ffi_typeof = ffi.typeof

ffi_cdef [[
void
nettle_yarrow256_init(struct yarrow256_ctx *ctx,
	       unsigned nsources,
	       struct yarrow_source *sources);

void
nettle_yarrow256_seed(struct yarrow256_ctx *ctx,
	       size_t length,
	       const uint8_t *seed_file);

int
nettle_yarrow256_update(struct yarrow256_ctx *ctx,
		 unsigned source, unsigned entropy,
		 size_t length, const uint8_t *data);

void
nettle_yarrow256_random(struct yarrow256_ctx *ctx, size_t length, uint8_t *dst);

int
nettle_yarrow256_is_seeded(struct yarrow256_ctx *ctx);

unsigned
nettle_yarrow256_needed_sources(struct yarrow256_ctx *ctx);

void
nettle_yarrow256_fast_reseed(struct yarrow256_ctx *ctx);

void
nettle_yarrow256_slow_reseed(struct yarrow256_ctx *ctx);
]]

return ffi_typeof [[
struct yarrow256_ctx {
  struct sha256_ctx pools[2];
  int seeded;
  struct aes256_ctx key;
  uint8_t counter[16];
  unsigned nsources;
  struct yarrow_source *sources;
}]]
