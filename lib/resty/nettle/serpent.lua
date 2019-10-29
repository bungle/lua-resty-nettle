local types = require "resty.nettle.types.common"
local context = require "resty.nettle.types.serpent"
local lib = require "resty.nettle.library"
local ffi = require "ffi"
local ffi_new = ffi.new
local ffi_copy = ffi.copy
local ffi_str = ffi.string
local ceil = math.ceil
local setmetatable = setmetatable

local serpent = {}
serpent.__index = serpent

function serpent.new(key)
  local len = #key
  if len ~= 16 and len ~= 24 and len ~= 32 then
    return nil, "the SERPENT supported key sizes are 128, 192, and 256 bits, and the 256 bits is " ..
      "the recommended key size"
  end
  local ct = ffi_new(context)
  if len == 16 then
    lib.nettle_serpent128_set_key(ct, key)
  elseif len == 24 then
    lib.nettle_serpent192_set_key(ct, key)
  elseif len == 32 then
    lib.nettle_serpent256_set_key(ct, key)
  end
  return setmetatable({ context = ct }, serpent)
end

function serpent:encrypt(src, len)
  len = len or #src
  local dln = ceil(len / 16) * 16
  local dst = ffi_new(types.uint8_t, dln)
  ffi_copy(dst, src, len)
  lib.nettle_serpent_encrypt(self.context, dln, dst, dst)
  return ffi_str(dst, dln)
end

function serpent:decrypt(src, len)
  len = len or #src
  local dln = ceil(len / 16) * 16
  local dst = ffi_new(types.uint8_t, dln)
  lib.nettle_serpent_decrypt(self.context, dln, dst, src)
  return ffi_str(dst, len)
end

return serpent
