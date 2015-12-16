require "resty.nettle"

local ffi      = require "ffi"
local ffi_cdef = ffi.cdef

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
]]