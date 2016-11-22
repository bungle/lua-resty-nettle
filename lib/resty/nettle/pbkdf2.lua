local lib        = require "resty.nettle.library"
local ffi        = require "ffi"
local ffi_new    = ffi.new
local ffi_typeof = ffi.typeof
local ffi_cdef   = ffi.cdef
local ffi_str    = ffi.string

ffi_cdef[[
void nettle_pbkdf2_hmac_sha1(size_t key_length, const uint8_t *key, unsigned iterations, size_t salt_length, const uint8_t *salt, size_t length, uint8_t *dst);
void nettle_pbkdf2_hmac_sha256(size_t key_length, const uint8_t *key, unsigned iterations, size_t salt_length, const uint8_t *salt, size_t length, uint8_t *dst);
]]

local uint8t = ffi_typeof "uint8_t[?]"
local pbkdf2 = {}

function pbkdf2.hmac_sha1(key, iterations, salt, len)
    local buf = ffi_new(uint8t, len)
    lib.nettle_pbkdf2_hmac_sha1(#key, key, iterations, #salt, salt, len, buf)
    return ffi_str(buf, len)
end

function pbkdf2.hmac_sha256(key, iterations, salt, len)
    local buf = ffi_new(uint8t, len)
    lib.nettle_pbkdf2_hmac_sha256(#key, key, iterations, #salt, salt, len, buf)
    return ffi_str(buf, len)
end

return pbkdf2
