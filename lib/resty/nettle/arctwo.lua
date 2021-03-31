local types = require "resty.nettle.types.common"
local context = require "resty.nettle.types.arctwo"
local lib = require "resty.nettle.library"
local ffi = require "ffi"
local ffi_new = ffi.new
local ffi_copy = ffi.copy
local ffi_str = ffi.string
local setmetatable = setmetatable

local arctwo = {}
arctwo.__index = arctwo

function arctwo.new(key, ekb)
  local len = #key
  if len < 1 or len > 128 then
    return nil, "the ARCTWO supported key sizes are between 1 and 1024 bits"
  end

  if ekb then
    if ekb < 0 or ekb > 1024 then
      return nil, "the ARCTWO supported effective key bits is between 1 and 1024 (0 is equivalent to 1024)"
    end
  else
    ekb = 1024
  end

  local ct = ffi_new(context)
  lib.nettle_arctwo_set_key_ekb(ct, len, key, ekb)
  return setmetatable({ context = ct }, arctwo)
end

function arctwo:encrypt(src, len)
  len = len or #src
  if len % 8 ~= 0 then
    return nil, "the ARCTWO input must be an integral multiple of the block size"
  end

  local dst = ffi_new(types.uint8_t, len)
  ffi_copy(dst, src, len)
  lib.nettle_arctwo_encrypt(self.context, len, dst, dst)
  return ffi_str(dst, len)
end

function arctwo:decrypt(src, len)
  len = len or #src
  if len % 8 ~= 0 then
    return nil, "the ARCTWO input must be an integral multiple of the block size"
  end
  local dst = ffi_new(types.uint8_t, len)
  lib.nettle_arctwo_decrypt(self.context, len, dst, src)
  return ffi_str(dst, len)
end

return arctwo
