local types = require "resty.nettle.types.common"
local context = require "resty.nettle.types.chacha"
local lib = require "resty.nettle.library"
local ffi = require "ffi"
local ffi_new = ffi.new
local ffi_copy = ffi.copy
local ffi_str = ffi.string
local setmetatable = setmetatable

local chacha = {}
chacha.__index = chacha

function chacha.new(key, nonce)
  local kl = #key
  if kl ~= 32 then
    return nil, "the ChaCha supported key size is 256 bits"
  end

  local nl
  if nonce then
    nl = #nonce
    if nl ~= 8 and nl ~= 12 then
      return nil, "the ChaCha supported nonce sizes are 64 bits and 96 bits"
    end
  end

  local ct = ffi_new(context)
  lib.nettle_chacha_set_key(ct, key)
  if nonce then
    if nl == 8 then
      lib.nettle_chacha_set_nonce(ct, nonce)
    elseif nl == 12 then
      lib.nettle_chacha_set_nonce96(ct, nonce)
    end
  end

  return setmetatable({ context = ct }, chacha)
end

function chacha:encrypt(src, len)
  len = len or #src
  local dst = ffi_new(types.uint8_t, len)
  ffi_copy(dst, src, len)
  lib.nettle_chacha_crypt(self.context, len, dst, dst)
  return ffi_str(dst, len)
end

function chacha:decrypt(src, len)
  len = len or #src
  local dst = ffi_new(types.uint8_t, len)
  lib.nettle_chacha_crypt(self.context, len, dst, src)
  return ffi_str(dst, len)
end

return chacha
