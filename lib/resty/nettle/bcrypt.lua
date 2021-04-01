local types = require "resty.nettle.types.common"
local random = require "resty.nettle.random"

require "resty.nettle.types.bcrypt"

local lib = require "resty.nettle.library"
local ffi = require "ffi"
local ffi_str = ffi.string

local bcrypt = {}

function bcrypt.hash(password, scheme, rounds, salt)
  scheme = scheme or "2b"
  rounds = rounds or 12
  salt   = salt   or random.bytes(16)

  local hash = types.zerobuffers(61)
  local ok = lib.nettle_blowfish_bcrypt_hash(hash, #password, password, #scheme, scheme, rounds, salt)
  if ok ~= 1 then
    return nil, "bcrypt hashing failed: invalid input"
  end

  return ffi_str(hash)
end

function bcrypt.verify(password, hash)
  if lib.nettle_blowfish_bcrypt_verify(#password, password, #hash, hash) ~= 1 then
    return nil, "unable to BCRYPT verify"
  end
  return true
end

return bcrypt
