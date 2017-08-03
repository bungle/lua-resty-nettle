local ffi      = require "ffi"
local ffi_cdef = ffi.cdef

ffi_cdef[[
typedef struct sha1_ctx {
  uint32_t state[5];
  uint64_t count;
  uint8_t block[64];
  unsigned int index;
} NETTLE_SHA1_CTX;
]]
