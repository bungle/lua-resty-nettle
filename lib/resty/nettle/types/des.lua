require "resty.nettle.types.cbc"
require "resty.nettle.types.ctr"

local ffi      = require "ffi"
local ffi_cdef = ffi.cdef

ffi_cdef[[
typedef struct des_ctx {
  uint32_t key[32];
} NETTLE_DES_CTX;
typedef struct des3_ctx {
  struct des_ctx des[3];
} NETTLE_DES3_CTX;
]]
