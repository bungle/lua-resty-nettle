local types = require "resty.nettle.types.common"
local random = require "resty.nettle.random"

require "resty.nettle.types.bcrypt"

local lib = require "resty.nettle.library"
local ffi = require "ffi"
local ffi_new = ffi.new
local ffi_str = ffi.string

local hash_buffer = ffi_new(types.uint8_t, 61)

local bcrypt = {}

function bcrypt.hash(password, salt, scheme, rounds)
  salt   = salt or random.bytes(16)
  scheme = scheme or "2b"
  rounds = rounds or 12

  local ok = lib.nettle_blowfish_bcrypt_hash(hash_buffer, #password, password, #scheme, scheme, rounds, salt)
  if ok ~= 1 then
    return nil, "bcrypt hashing failed: invalid input"
  end

  return ffi_str(hash_buffer)
end

function bcrypt.verify(password, hash)
  return lib.nettle_blowfish_bcrypt_verify(#password, password, #hash, hash) == 1
end

return bcrypt
