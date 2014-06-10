local ffi        = require "ffi"
local ffi_cdef   = ffi.cdef

ffi_cdef[[
typedef struct aes128_ctx {
  uint32_t keys[44];
} AES128_CTX;
typedef struct aes192_ctx {
  uint32_t keys[52];
} AES192_CTX;
typedef struct aes256_ctx {
  uint32_t keys[60];
} AES256_CTX;
]]