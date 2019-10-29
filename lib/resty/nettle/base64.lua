local types = require "resty.nettle.types.common"
local context = require "resty.nettle.types.base64"
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

function encoder.new(urlsafe)
  local ctx = ffi_new(context.encode)
  if urlsafe then
    lib.nettle_base64url_encode_init(ctx)
  else
    lib.nettle_base64_encode_init(ctx)
  end
  return setmetatable({ context = ctx }, encoder)
end

function encoder:single(src)
  local len = lib.nettle_base64_encode_single(self.context, types.char_2, byte(src))
  return ffi_str(types.char_2, len), tonumber(len)
end

function encoder:update(src)
  local len = #src
  local dln = floor((len * 8 + 4) / 6)
  local dst = ffi_new(types.char, dln)
  len = lib.nettle_base64_encode_update(self.context, dst, len, src)
  return ffi_str(dst, len), tonumber(len)
end

function encoder:final()
  local len = lib.nettle_base64_encode_final(self.context, types.char_3)
  return ffi_str(types.char_3, len), tonumber(len)
end

local decoder = {}
decoder.__index = decoder

function decoder.new(urlsafe)
  local ctx = ffi_new(context.decode)
  if urlsafe then
    lib.nettle_base64url_decode_init(ctx)
  else
    lib.nettle_base64_decode_init(ctx)
  end
  return setmetatable({ context = ctx }, decoder)
end

function decoder:single(src)
  local len = lib.nettle_base64_decode_single(self.context, types.uint8_t_1, byte(src))
  return ffi_str(types.uint8_t_1, len), len
end

function decoder:update(src)
  local len = #src
  local dln = floor((len + 1) * 6 / 8)
  local dst = ffi_new(types.uint8_t, dln)
  if lib.nettle_base64_decode_update(self.context, types.size_t_8, dst, len, src) ~= 1 then
    return nil, "unable to decode base64 data"
  end
  len = tonumber(types.size_t_8[0])
  return ffi_str(dst, len), len
end

function decoder:final()
  if lib.nettle_base64_decode_final(self.context) ~= 1 then
    return nil, "final padding of base64 is incorrect"
  end
  return true
end

local base64 = setmetatable({ encoder = encoder, decoder = decoder }, {
  __call = function(_, src)
    local len = #src
    local dln = floor((len + 2) / 3) * 4
    local dst = ffi_new(types.char, dln)
    lib.nettle_base64_encode_raw(dst, len, src)
    return ffi_str(dst, dln)
  end
})

function base64.encode(src, urlsafe)
  local ctx = ffi_new(context.encode)
  if urlsafe then
    lib.nettle_base64url_encode_init(ctx)
  else
    lib.nettle_base64_encode_init(ctx)
  end
  local len = #src
  local dln = floor((len * 8 + 4) / 6)
  local dst = ffi_new(types.char, dln)
  dst = ffi_str(dst, lib.nettle_base64_encode_update(ctx, dst, len, src))
  local fnl = lib.nettle_base64_encode_final(ctx, types.char_3)
  if fnl > 0 then
    return dst .. ffi_str(types.char_3, fnl)
  end
  return dst
end

function base64.decode(src, urlsafe)
  local ctx = ffi_new(context.decode)
  local len = #src
  local dln = floor((len + 1) * 6 / 8)
  local dst = ffi_new(types.uint8_t, dln)
  if urlsafe then
    lib.nettle_base64url_decode_init(ctx)
  else
    lib.nettle_base64_decode_init(ctx)
  end
  if lib.nettle_base64_decode_update(ctx, types.size_t_8, dst, len, src) ~= 1 then
    return nil, "unable to decode base64 data"
  end
  if lib.nettle_base64_decode_final(ctx) ~= 1 then
    return nil, "final padding of base64 is incorrect"
  end
  return ffi_str(dst, types.size_t_8[0])
end

function base64.urlencode(src)
  return base64.encode(src, true)
end

function base64.urldecode(src)
  return base64.decode(src, true)
end

return base64
