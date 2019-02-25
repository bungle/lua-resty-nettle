require "resty.nettle.types.cbc"
require "resty.nettle.types.ctr"

local ffi = require "ffi"
local ffi_cdef = ffi.cdef
local ffi_typeof = ffi.typeof

ffi_cdef [[
int
nettle_des_set_key(struct des_ctx *ctx, const uint8_t *key);

void
nettle_des_encrypt(const struct des_ctx *ctx,
                   size_t length, uint8_t *dst,
                   const uint8_t *src);

void
nettle_des_decrypt(const struct des_ctx *ctx,
                   size_t length, uint8_t *dst,
                   const uint8_t *src);

int
nettle_des_check_parity(size_t length, const uint8_t *key);

void
nettle_des_fix_parity(size_t length, uint8_t *dst,
                      const uint8_t *src);

int
nettle_des3_set_key(struct des3_ctx *ctx, const uint8_t *key);

void
nettle_des3_encrypt(const struct des3_ctx *ctx,
                    size_t length, uint8_t *dst,
                    const uint8_t *src);

void
nettle_des3_decrypt(const struct des3_ctx *ctx,
                    size_t length, uint8_t *dst,
                    const uint8_t *src);
]]

return {
  des = ffi_typeof [[
struct des_ctx {
  uint32_t key[32];
}]],
  des3 = ffi_typeof [[
struct des3_ctx {
  struct des_ctx des[3];
}]],
}
