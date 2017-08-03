local ffi      = require "ffi"
local ffi_cdef = ffi.cdef

ffi_cdef[[
typedef struct sha256_ctx {
  uint32_t state[8];
  uint64_t count;
  uint8_t block[64];
  unsigned int index;
} NETTLE_SHA256_CTX;
typedef struct sha512_ctx {
  uint64_t state[8];
  uint64_t count_low, count_high;
  uint8_t block[128];
  unsigned int index;
} NETTLE_SHA512_CTX;
]]
