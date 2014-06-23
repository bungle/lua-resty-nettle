require "resty.nettle"

local ffi        = require "ffi"
local ffi_cdef   = ffi.cdef

ffi_cdef[[
typedef struct eax_key {
  union nettle_block16 pad_block;
  union nettle_block16 pad_partial;
} EAX_KEY;
typedef struct eax_ctx {
  union nettle_block16 omac_nonce;
  union nettle_block16 omac_data;
  union nettle_block16 omac_message;
  union nettle_block16 ctr;
} EAX_CTX;
]]