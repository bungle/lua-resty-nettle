local types = require "resty.nettle.types.common"
local context = require "resty.nettle.types.blowfish"
local lib = require "resty.nettle.library"
local ffi = require "ffi"
local ffi_new = ffi.new
local ffi_copy = ffi.copy
local ffi_str = ffi.string
local ceil = math.ceil
local setmetatable = setmetatable

local blowfish = {}
blowfish.__index = blowfish

function blowfish.new(key)
  local len = #key
  if len < 8 or len > 56 then
    return nil, "the BLOWFISH supported key sizes are between 64 and 448 bits"
  end
  local ct = ffi_new(context)
  local wk = lib.nettle_blowfish_set_key(ct, len, key)
  return setmetatable({ context = ct }, blowfish), wk ~= 1
end

function blowfish:encrypt(src, len)
  len = len or #src
  local dln = ceil(len / 8) * 8
  local dst = ffi_new(types.uint8_t, dln)
  ffi_copy(dst, src, len)
  lib.nettle_blowfish_encrypt(self.context, dln, dst, dst)
  return ffi_str(dst, dln)
end

function blowfish:decrypt(src, len)
  len = len or #src
  local dln = ceil(len / 8) * 8
  local dst = ffi_new(types.uint8_t, dln)
  lib.nettle_blowfish_decrypt(self.context, dln, dst, src)
  return ffi_str(dst, len)
end

return blowfish
