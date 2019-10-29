local ffi = require "ffi"
local ffi_cdef = ffi.cdef

ffi_cdef [[
void
nettle_pbkdf2_hmac_sha1(size_t key_length, const uint8_t *key,
                        unsigned iterations,
                        size_t salt_length, const uint8_t *salt,
                        size_t length, uint8_t *dst);

void
nettle_pbkdf2_hmac_sha256(size_t key_length, const uint8_t *key,
                          unsigned iterations,
                          size_t salt_length, const uint8_t *salt,
                          size_t length, uint8_t *dst);
]]
