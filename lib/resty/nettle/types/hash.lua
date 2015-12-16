local ffi      = require "ffi"
local ffi_cdef = ffi.cdef

ffi_cdef[[
typedef void nettle_hash_init_func(void *ctx);
typedef void nettle_hash_update_func(void *ctx, size_t length, const uint8_t *src);
typedef void nettle_hash_digest_func(void *ctx, size_t length, uint8_t *dst);
struct nettle_hash {
  const char *name;
  unsigned context_size;
  unsigned digest_size;
  unsigned block_size;
  nettle_hash_init_func *init;
  nettle_hash_update_func *update;
  nettle_hash_digest_func *digest;
};
extern const struct nettle_hash * const nettle_hashes[];
]]