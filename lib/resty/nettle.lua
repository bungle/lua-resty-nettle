local ffi        = require "ffi"
local ffi_load   = ffi.load
local ffi_cdef   = ffi.cdef

ffi_cdef[[
typedef void nettle_cipher_func(const void *ctx, size_t length, uint8_t *dst, const uint8_t *src);
]]

return ffi_load("libnettle")