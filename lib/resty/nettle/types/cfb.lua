require "resty.nettle.types.nettle-types"

local ffi = require "ffi"
local ffi_cdef = ffi.cdef

ffi_cdef [[
void
nettle_cfb_encrypt(const void *ctx, nettle_cipher_func *f,
	    size_t block_size, uint8_t *iv,
	    size_t length, uint8_t *dst,
	    const uint8_t *src);

void
nettle_cfb_decrypt(const void *ctx, nettle_cipher_func *f,
	    size_t block_size, uint8_t *iv,
	    size_t length, uint8_t *dst,
	    const uint8_t *src);

void
nettle_cfb8_encrypt(const void *ctx, nettle_cipher_func *f,
	     size_t block_size, uint8_t *iv,
	     size_t length, uint8_t *dst,
	     const uint8_t *src);

void
nettle_cfb8_decrypt(const void *ctx, nettle_cipher_func *f,
	     size_t block_size, uint8_t *iv,
	     size_t length, uint8_t *dst,
	     const uint8_t *src);
]]
