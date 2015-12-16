require "resty.nettle"
local ffi      = require "ffi"
local ffi_cdef = ffi.cdef

ffi_cdef[[
typedef struct nettle_buffer {
  uint8_t *contents;
  size_t alloc;
  void *realloc_ctx;
  nettle_realloc_func *realloc;
  size_t size;
} NETTLE_BUFFER;
]]