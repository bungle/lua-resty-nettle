local ffi = require "ffi"
local ffi_cdef = ffi.cdef
local ffi_typeof = ffi.typeof


ffi_cdef [[
struct sha3_state {
  uint64_t a[25];
};

void
nettle_sha3_224_init(struct sha3_224_ctx *ctx);

void
nettle_sha3_224_update(struct sha3_224_ctx *ctx,
                       size_t length,
		               const uint8_t *data);

void
nettle_sha3_224_digest(struct sha3_224_ctx *ctx,
                       size_t length,
                       uint8_t *digest);

void
nettle_sha3_256_init(struct sha3_256_ctx *ctx);

void
nettle_sha3_256_update(struct sha3_256_ctx *ctx,
                       size_t length,
                       const uint8_t *data);

void
nettle_sha3_256_digest(struct sha3_256_ctx *ctx,
                       size_t length,
                       uint8_t *digest);

void
nettle_sha3_384_init (struct sha3_384_ctx *ctx);

void
nettle_sha3_384_update(struct sha3_384_ctx *ctx,
                       size_t length,
		               const uint8_t *data);

void
nettle_sha3_384_digest(struct sha3_384_ctx *ctx,
                       size_t length,
                       uint8_t *digest);

void
nettle_sha3_512_init(struct sha3_512_ctx *ctx);

void
nettle_sha3_512_update(struct sha3_512_ctx *ctx,
                        size_t length,
                        const uint8_t *data);

void
nettle_sha3_512_digest(struct sha3_512_ctx *ctx,
                       size_t length,
                       uint8_t *digest);
]]


return {
  sha3_224 = ffi_typeof [[
struct sha3_224_ctx {
  struct sha3_state state;
  unsigned index;
  uint8_t block[144];
}]],
  sha3_256 = ffi_typeof [[
struct sha3_256_ctx {
  struct sha3_state state;
  unsigned index;
  uint8_t block[136];
}]],
  sha3_384 = ffi_typeof [[
struct sha3_384_ctx {
  struct sha3_state state;
  unsigned index;
  uint8_t block[104];
}]],
  sha3_512 = ffi_typeof [[
struct sha3_512_ctx {
  struct sha3_state state;
  unsigned index;
  uint8_t block[72];
}]],
}
