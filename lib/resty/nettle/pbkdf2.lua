require "resty.nettle.types.pbkdf2"

local types = require "resty.nettle.types.common"
local lib = require "resty.nettle.library"
local ffi = require "ffi"
local ffi_new = ffi.new
local ffi_str = ffi.string

local pbkdf2 = {}

function pbkdf2.hmac_sha1(key, iterations, salt, len)
  local buf = ffi_new(types.uint8_t, len)
  lib.nettle_pbkdf2_hmac_sha1(#key, key, iterations, #salt, salt, len, buf)
  return ffi_str(buf, len)
end

function pbkdf2.hmac_sha256(key, iterations, salt, len)
  local buf = ffi_new(types.uint8_t, len)
  lib.nettle_pbkdf2_hmac_sha256(#key, key, iterations, #salt, salt, len, buf)
  return ffi_str(buf, len)
end

return pbkdf2
