local types = require "resty.nettle.types.common"
local context = require "resty.nettle.types.base16"
local lib = require "resty.nettle.library"
local ffi = require "ffi"
local ffi_new = ffi.new
local ffi_str = ffi.string
local byte = string.byte
local floor = math.floor
local tonumber = tonumber
local setmetatable = setmetatable

local encoder = {}
encoder.__index = encoder

function encoder.new()
  return setmetatable({}, encoder)
end

function encoder.single(_, src)
  lib.nettle_base16_encode_single(types.char_2, (byte(src)))
  return ffi_str(types.char_2, 2)
end

function encoder.update(_, src)
  local len = #src
  local dln = len * 2
  local dst = ffi_new(types.char, dln)
  lib.nettle_base16_encode_update(dst, len, src)
  return ffi_str(dst, dln)
end

local decoder = {}
decoder.__index = decoder

function decoder.new()
  local ctx = ffi_new(context)
  lib.nettle_base16_decode_init(ctx)
  return setmetatable({ context = ctx }, decoder)
end

function decoder:single(src)
  local len = lib.nettle_base16_decode_single(self.context, types.uint8_t_1, byte(src))
  return ffi_str(types.uint8_t_1, len), len
end

function decoder:update(src)
  local len = #src
  local dln = floor((len + 1) / 2)
  local dst = ffi_new(types.uint8_t, dln)
  if lib.nettle_base16_decode_update(self.context, types.size_t_8, dst, len, src) ~= 1 then
    return nil, "unable to decode base16 data"
  end
  len = tonumber(types.size_t_8[0])
  return ffi_str(dst, len), len
end

function decoder:final()
  if lib.nettle_base16_decode_final(self.context) ~= 1 then
    return nil, "end of the base16 data is incorrect"
  end
  return true
end

local base16 = { encoder = encoder, decoder = decoder }

function base16.encode(src)
  local len = #src
  local dln = len * 2
  local dst = ffi_new(types.uint8_t, dln)
  lib.nettle_base16_encode_update(dst, len, src)
  return ffi_str(dst, dln)
end

function base16.decode(src)
  local ctx = ffi_new(context)
  local len = #src
  local dln = floor((len + 1) / 2)
  local dst = ffi_new(types.uint8_t, dln)
  lib.nettle_base16_decode_init(ctx)
  if lib.nettle_base16_decode_update(ctx, types.size_t_8, dst, len, src) ~= 1 then
    return nil, "unable to decode base16 data"
  end
  if lib.nettle_base16_decode_final(ctx) ~= 1 then
    return nil, "end of the base16 data is incorrect"
  end
  return ffi_str(dst, types.size_t_8[0])
end

return base16
