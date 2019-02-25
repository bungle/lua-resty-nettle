local types = require "resty.nettle.types.common"
local context = require "resty.nettle.types.salsa20"
local lib = require "resty.nettle.library"
local ffi = require "ffi"
local ffi_new = ffi.new
local ffi_copy = ffi.copy
local ffi_str = ffi.string
local setmetatable = setmetatable

local salsa20r12 = {}
salsa20r12.__index = salsa20r12

function salsa20r12:encrypt(src, len)
  len = len or #src
  local dst = ffi_new(types.uint8_t, len)
  ffi_copy(dst, src, len)
  lib.nettle_salsa20r12_crypt(self.context, len, dst, dst)
  return ffi_str(dst, len)
end

function salsa20r12:decrypt(src, len)
  len = len or #src
  local dst = ffi_new(types.uint8_t, len)
  lib.nettle_salsa20r12_crypt(self.context, len, dst, src)
  return ffi_str(dst, len)
end

local salsa20 = {}
salsa20.__index = salsa20

function salsa20.new(key, nonce, rounds)
  local len = #key
  if len ~= 16 and len ~= 32 then
    return nil, "the Salsa20 supported key sizes are 128, and 256 bits"
  end
  local ctx = ffi_new(context)
  if len == 16 then
    lib.nettle_salsa20_128_set_key(ctx, key)
  else
    lib.nettle_salsa20_256_set_key(ctx, key)
  end

  if nonce then
    if #nonce ~= 8 then
      return nil, "the Salsa20 supported nonce size is 64 bits"
    end

    lib.nettle_salsa20_set_nonce(ctx, nonce)
  end

  rounds = rounds or 20
  if rounds ~= 12 and rounds ~= 20 then
    return nil, "the Salsa20 supported rounds are 12, and 20. The recommended rounds is 20"
  end

  if rounds == 20 then
    return setmetatable({ context = ctx }, salsa20)
  end

  return setmetatable({ context = ctx }, salsa20r12)
end

function salsa20:encrypt(src, len)
  len = len or #src
  local dst = ffi_new(types.uint8_t, len)
  ffi_copy(dst, src, len)
  lib.nettle_salsa20_crypt(self.context, len, dst, dst)
  return ffi_str(dst, len)
end

function salsa20:decrypt(src, len)
  len = len or #src
  local dst = ffi_new(types.uint8_t, len)
  lib.nettle_salsa20_crypt(self.context, len, dst, src)
  return ffi_str(dst, len)
end

return salsa20
