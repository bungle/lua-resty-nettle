local ffi = require "ffi"
local ffi_cdef = ffi.cdef

ffi_cdef [[
int
nettle_blowfish_bcrypt_hash(uint8_t *dst,
                            size_t lenkey, const uint8_t *key,
                            size_t lenscheme, const uint8_t *scheme,
                            int log2rounds,
                            const uint8_t *salt);
int
nettle_blowfish_bcrypt_verify(size_t lenkey, const uint8_t *key,
                              size_t lenhashed, const uint8_t *hashed);
]]
