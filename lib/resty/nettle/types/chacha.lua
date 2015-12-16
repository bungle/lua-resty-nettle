local ffi      = require "ffi"
local ffi_cdef = ffi.cdef

ffi_cdef[[
typedef struct chacha_ctx {
  uint32_t state[16];
} CHACHA_CTX;
]]