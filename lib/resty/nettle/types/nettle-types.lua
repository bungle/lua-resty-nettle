local ffi = require "ffi"
local ffi_cdef = ffi.cdef

ffi_cdef [[
union nettle_block16 {
  uint8_t b[16];
  unsigned long w[16 / sizeof(unsigned long)];
  uint64_t u64[2];
};

typedef void nettle_random_func(void *ctx,
                                size_t length, uint8_t *dst);

typedef void nettle_progress_func(void *ctx, int c);

typedef void *nettle_realloc_func(void *ctx, void *p, size_t length);

typedef void nettle_set_key_func(void *ctx, const uint8_t *key);

typedef void nettle_cipher_func(const void *ctx,
                                size_t length, uint8_t *dst,
                                const uint8_t *src);

typedef void nettle_crypt_func(void *ctx,
                               size_t length, uint8_t *dst,
                               const uint8_t *src);

typedef void nettle_hash_init_func(void *ctx);
typedef void nettle_hash_update_func(void *ctx,
                                     size_t length,
                                     const uint8_t *src);

typedef void nettle_hash_digest_func(void *ctx,
                                     size_t length, uint8_t *dst);
]]
