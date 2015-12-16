require "resty.nettle.types.cbc"
require "resty.nettle.types.ctr"

local ffi      = require "ffi"
local ffi_cdef = ffi.cdef

ffi_cdef[[
typedef struct des_ctx {
  uint32_t key[32];
} DES_CTX;
typedef struct des3_ctx {
  struct des_ctx des[3];
} DES3_CTX;
]]
