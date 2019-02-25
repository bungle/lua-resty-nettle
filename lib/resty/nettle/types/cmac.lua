require "resty.nettle.types.nettle-types"
require "resty.nettle.types.aes"

local ffi = require "ffi"
local ffi_cdef = ffi.cdef
local ffi_typeof = ffi.typeof

ffi_cdef [[
struct cmac128_ctx {
  union nettle_block16 K1;
  union nettle_block16 K2;
  union nettle_block16 X;
  union nettle_block16 block;
  size_t index;
};

void
nettle_cmac_aes128_set_key(struct cmac_aes128_ctx *ctx, const uint8_t *key);

void
nettle_cmac_aes128_update(struct cmac_aes128_ctx *ctx,
                          size_t length, const uint8_t *data);

void
nettle_cmac_aes128_digest(struct cmac_aes128_ctx *ctx,
                          size_t length, uint8_t *digest);

void
nettle_cmac_aes256_set_key(struct cmac_aes256_ctx *ctx, const uint8_t *key);

void
nettle_cmac_aes256_update(struct cmac_aes256_ctx *ctx,
                          size_t length, const uint8_t *data);

void
nettle_cmac_aes256_digest(struct cmac_aes256_ctx *ctx,
                          size_t length, uint8_t *digest);
]]

return {
  aes128 = ffi_typeof [[
struct cmac_aes128_ctx {
  struct cmac128_ctx ctx;
  struct aes128_ctx cipher;
}]],
  aes256 = ffi_typeof [[
struct cmac_aes256_ctx {
  struct cmac128_ctx ctx;
  struct aes256_ctx cipher;
}]],
}
