require "resty.nettle.library"

local ffi      = require "ffi"
local ffi_cdef = ffi.cdef

ffi_cdef[[
void nettle_ctr_crypt(const void *ctx, nettle_cipher_func *f, size_t block_size, uint8_t *ctr, size_t length, uint8_t *dst, const uint8_t *src);
]]
