require "resty.nettle.types.pbkdf2"

local types = require "resty.nettle.types.common"
local lib = require "resty.nettle.library"
local ffi = require "ffi"
local ffi_str = ffi.string

local pbkdf2 = {}

function pbkdf2.hmac_sha1(key, iterations, salt, len)
  len = len or 20
  local buf = types.buffers(len)
  lib.nettle_pbkdf2_hmac_sha1(#key, key, iterations, #salt, salt, len, buf)
  return ffi_str(buf, len)
end

function pbkdf2.hmac_sha256(key, iterations, salt, len)
  len = len or 32
  local buf = types.buffers(len)
  lib.nettle_pbkdf2_hmac_sha256(#key, key, iterations, #salt, salt, len, buf)
  return ffi_str(buf, len)
end

function pbkdf2.hmac_sha384(key, iterations, salt, len)
  len = len or 48
  local buf = types.buffers(len)
  lib.nettle_pbkdf2_hmac_sha384(#key, key, iterations, #salt, salt, len, buf)
  return ffi_str(buf, len)
end

function pbkdf2.hmac_sha512(key, iterations, salt, len)
  len = len or 64
  local buf = types.buffers(len)
  lib.nettle_pbkdf2_hmac_sha512(#key, key, iterations, #salt, salt, len, buf)
  return ffi_str(buf, len)
end

function pbkdf2.hmac_gosthash94cp(key, iterations, salt, len)
  len = len or 32
  local buf = types.buffers(len)
  lib.nettle_pbkdf2_hmac_gosthash94cp(#key, key, iterations, #salt, salt, len, buf)
  return ffi_str(buf, len)
end

return pbkdf2
