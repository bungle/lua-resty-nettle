local ffi        = require "ffi"
local ffi_cdef   = ffi.cdef

ffi_cdef[[
typedef struct aes128_ctx {
  uint32_t keys[44];
} AES128_CTX;
]]