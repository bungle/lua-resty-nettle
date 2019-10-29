local types = require "resty.nettle.types.common"
local context = require "resty.nettle.types.arcfour"
local lib = require "resty.nettle.library"
local ffi = require "ffi"
local ffi_new = ffi.new
local ffi_copy = ffi.copy
local ffi_str = ffi.string
local setmetatable = setmetatable

local arcfour = {}
arcfour.__index = arcfour

function arcfour.new(key)
  local len = #key
  if len < 1 or len > 32 then
    return nil, "the ARCFOUR supported key sizes are between 1 and 256 bits"
  end

  local ct = ffi_new(context)
  if len == 16 then
    lib.nettle_arcfour128_set_key(ct, key)
  else
    lib.nettle_arcfour_set_key(ct, len, key)
  end

  return setmetatable({ context = ct }, arcfour)
end

function arcfour:encrypt(src, len)
  len = len or #src
  local dst = ffi_new(types.uint8_t, len)
  ffi_copy(dst, src, len)
  lib.nettle_arcfour_crypt(self.context, len, dst, dst)
  return ffi_str(dst, len)
end

function arcfour:decrypt(src, len)
  len = len or #src
  local dst = ffi_new(types.uint8_t, len)
  lib.nettle_arcfour_crypt(self.context, len, dst, src)
  return ffi_str(dst, len)
end

return arcfour
