local ffi = require "ffi"
local ffi_cdef = ffi.cdef
local ffi_typeof = ffi.typeof

ffi_cdef [[
void
nettle_arctwo_set_key_ekb(struct arctwo_ctx *ctx,
		                      size_t length, const uint8_t * key, unsigned ekb);

void
nettle_arctwo_set_key(struct arctwo_ctx *ctx, size_t length, const uint8_t *key);

void
nettle_arctwo40_set_key(struct arctwo_ctx *ctx, const uint8_t *key);

void
nettle_arctwo64_set_key(struct arctwo_ctx *ctx, const uint8_t *key);

void
nettle_arctwo128_set_key(struct arctwo_ctx *ctx, const uint8_t *key);

void
nettle_arctwo_set_key_gutmann(struct arctwo_ctx *ctx,
			                        size_t length, const uint8_t *key);
void
nettle_arctwo128_set_key_gutmann(struct arctwo_ctx *ctx,
			                           const uint8_t *key);

void
nettle_arctwo_encrypt(struct arctwo_ctx *ctx,
		                  size_t length, uint8_t *dst, const uint8_t *src);
void
nettle_arctwo_decrypt(struct arctwo_ctx *ctx,
		                  size_t length, uint8_t *dst, const uint8_t *src);
]]

return ffi_typeof [[
struct arctwo_ctx {
  uint16_t S[64];
}]]
