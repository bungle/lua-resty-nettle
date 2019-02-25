local types = require "resty.nettle.types.common"
local context = require "resty.nettle.types.chacha-poly1305"
local lib = require "resty.nettle.library"
local ffi = require "ffi"
local ffi_new = ffi.new
local ffi_str = ffi.string
local setmetatable = setmetatable

local chacha_poly1305 = {}
chacha_poly1305.__index = chacha_poly1305

function chacha_poly1305.new(key, nonce, ad)
  local kl = #key
  if kl ~= 32 then
    return nil, "the ChaCha-Poly1305 supported key size is 256 bits"
  end
  local nl = #nonce
  if nl ~= 16 then
    return nil, "the ChaCha-Poly1305 supported nonce size is 128 bits"
  end
  local ct = ffi_new(context)
  lib.nettle_chacha_poly1305_set_key(ct, key)
  lib.nettle_chacha_poly1305_set_nonce(ct, nonce)
  if ad then
    lib.nettle_chacha_poly1305_update(ct, #ad, ad)
  end
  return setmetatable({ context = ct }, chacha_poly1305)
end

function chacha_poly1305:encrypt(src)
  local len = #src
  local ctx = self.context
  local dst = ffi_new(types.uint8_t, len)
  lib.nettle_chacha_poly1305_encrypt(ctx, len, dst, src)
  lib.nettle_chacha_poly1305_digest(ctx, 16, types.uint8_t_16)
  return ffi_str(dst, len), ffi_str(types.uint8_t_16, 16)
end

function chacha_poly1305:decrypt(src)
  local len = #src
  local ctx = self.context
  local dst = ffi_new(types.uint8_t, len)
  lib.nettle_chacha_poly1305_decrypt(ctx, len, dst, src)
  lib.nettle_chacha_poly1305_digest(ctx, 16, types.uint8_t_16)
  return ffi_str(dst, len), ffi_str(types.uint8_t_16, 16)
end

return chacha_poly1305
