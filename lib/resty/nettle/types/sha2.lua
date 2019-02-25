local ffi = require "ffi"
local ffi_cdef = ffi.cdef
local ffi_typeof = ffi.typeof

ffi_cdef [[
void
nettle_sha256_init(struct sha256_ctx *ctx);

void
nettle_sha256_update(struct sha256_ctx *ctx,
                     size_t length,
                     const uint8_t *data);

void
nettle_sha256_digest(struct sha256_ctx *ctx,
                     size_t length,
                     uint8_t *digest);

void
nettle_sha224_init(struct sha256_ctx *ctx);

void
nettle_sha224_digest(struct sha256_ctx *ctx,
                     size_t length,
                     uint8_t *digest);

void
nettle_sha512_init(struct sha512_ctx *ctx);

void
nettle_sha512_update(struct sha512_ctx *ctx,
                     size_t length,
                     const uint8_t *data);

void
nettle_sha512_digest(struct sha512_ctx *ctx,
                     size_t length,
                     uint8_t *digest);

void
nettle_sha384_init(struct sha512_ctx *ctx);

void
nettle_sha384_digest(struct sha512_ctx *ctx,
                     size_t length,
                     uint8_t *digest);

void
nettle_sha512_224_init(struct sha512_ctx *ctx);

void
nettle_sha512_224_digest(struct sha512_ctx *ctx,
                         size_t length,
                         uint8_t *digest);

void
nettle_sha512_256_init(struct sha512_ctx *ctx);

void
nettle_sha512_256_digest(struct sha512_ctx *ctx,
                         size_t length,
                         uint8_t *digest);
]]


return {
  sha256 = ffi_typeof [[
struct sha256_ctx {
  uint32_t state[8];
  uint64_t count;
  unsigned int index;
  uint8_t block[64];
}]],
  sha512 = ffi_typeof [[
struct sha512_ctx {
  uint64_t state[8];
  uint64_t count_low, count_high;
  unsigned int index;
  uint8_t block[128];
}]],
}
