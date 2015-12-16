require "resty.nettle"

local ffi      = require "ffi"
local ffi_cdef = ffi.cdef

ffi_cdef[[
typedef struct ccm_ctx {
  union nettle_block16 ctr;
  union nettle_block16 tag;
  unsigned int blength;
} CCM_CTX;
]]