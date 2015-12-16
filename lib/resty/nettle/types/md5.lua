local ffi      = require "ffi"
local ffi_cdef = ffi.cdef

ffi_cdef[[
typedef struct md5_ctx {
  uint32_t state[4];
  uint64_t count;
  uint8_t block[64];
  unsigned index;
} MD5_CTX;
]]