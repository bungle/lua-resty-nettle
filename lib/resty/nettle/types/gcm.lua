require "resty.nettle"
require "resty.nettle.types.aes"

local ffi        = require "ffi"
local ffi_cdef   = ffi.cdef

ffi_cdef[[
typedef struct gcm_key {
  union nettle_block16 h[256];
} GCM_KEY;
typedef struct gcm_ctx {
  union nettle_block16 iv;
  union nettle_block16 ctr;
  union nettle_block16 x;
  uint64_t auth_size;
  uint64_t data_size;
} GCM_CTX;
typedef struct gcm_aes128_ctx {
  struct gcm_key key;
  struct gcm_ctx gcm;
  struct aes128_ctx cipher;
} GCM_AES128_CTX;
typedef struct gcm_aes192_ctx {
  struct gcm_key key;
  struct gcm_ctx gcm;
  struct aes192_ctx cipher;
} GCM_AES192_CTX;
typedef struct gcm_aes256_ctx {
  struct gcm_key key;
  struct gcm_ctx gcm;
  struct aes256_ctx cipher;
} GCM_AES256_CTX;
]]