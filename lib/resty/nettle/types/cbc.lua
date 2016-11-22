require "resty.nettle.library"

local ffi      = require "ffi"
local ffi_cdef = ffi.cdef

ffi_cdef[[
void nettle_cbc_encrypt(const void *ctx, nettle_cipher_func *f, size_t block_size, uint8_t *iv, size_t length, uint8_t *dst, const uint8_t *src);
void nettle_cbc_decrypt(const void *ctx, nettle_cipher_func *f, size_t block_size, uint8_t *iv, size_t length, uint8_t *dst, const uint8_t *src);
]]
