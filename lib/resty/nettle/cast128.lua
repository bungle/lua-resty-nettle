local types = require "resty.nettle.types.common"
local context = require "resty.nettle.types.cast128"
local lib = require "resty.nettle.library"
local ffi = require "ffi"
local ffi_new = ffi.new
local ffi_copy = ffi.copy
local ffi_str = ffi.string
local ceil = math.ceil
local setmetatable = setmetatable

local cast128 = {}
cast128.__index = cast128

function cast128.new(key)
  local len = #key
  if len < 5 or len > 16 then
    return nil, "the CAST128 supported key sizes are between 40 and 128 bits"
  end
  local ct = ffi_new(context)
  if len == 16 then
    lib.nettle_cast128_set_key(ct, key)
  else
    lib.nettle_cast5_set_key(ct, len, key)
  end
  return setmetatable({ context = ct }, cast128)
end

function cast128:encrypt(src, len)
  len = len or #src
  local dln = ceil(len / 8) * 8
  local dst = ffi_new(types.uint8_t, dln)
  ffi_copy(dst, src, len)
  lib.nettle_cast128_encrypt(self.context, dln, dst, dst)
  return ffi_str(dst, dln)
end

function cast128:decrypt(src, len)
  len = len or #src
  local dln = ceil(len / 8) * 8
  local dst = ffi_new(types.uint8_t, dln)
  lib.nettle_cast128_decrypt(self.context, dln, dst, src)
  return ffi_str(dst, len)
end

return cast128
