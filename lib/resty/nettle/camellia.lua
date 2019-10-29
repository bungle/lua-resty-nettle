local camellia_context = require "resty.nettle.types.camellia"
local gcm_context = require "resty.nettle.types.gcm"
local types = require "resty.nettle.types.common"
local lib = require "resty.nettle.library"
local ffi = require "ffi"
local ffi_new = ffi.new
local ffi_copy = ffi.copy
local ffi_str = ffi.string
local ceil = math.ceil
local lower = string.lower
local setmetatable = setmetatable

local ciphers = {
  ecb = {
    [128] = {
      setkey = lib.nettle_camellia128_set_encrypt_key,
      invert = lib.nettle_camellia128_invert_key,
      encrypt = lib.nettle_camellia128_crypt,
      decrypt = lib.nettle_camellia128_crypt,
      context = camellia_context.camellia128
    },
    [192] = {
      setkey = lib.nettle_camellia192_set_encrypt_key,
      invert = lib.nettle_camellia256_invert_key,
      encrypt = lib.nettle_camellia256_crypt,
      decrypt = lib.nettle_camellia256_crypt,
      context = camellia_context.camellia192
    },
    [256] = {
      setkey = lib.nettle_camellia256_set_encrypt_key,
      invert = lib.nettle_camellia256_invert_key,
      encrypt = lib.nettle_camellia256_crypt,
      decrypt = lib.nettle_camellia256_crypt,
      context = camellia_context.camellia256
    }
  },
  gcm = {
    iv_size = 12,
    [128] = {
      setkey = lib.nettle_gcm_camellia128_set_key,
      setiv = lib.nettle_gcm_camellia128_set_iv,
      update = lib.nettle_gcm_camellia128_update,
      encrypt = lib.nettle_gcm_camellia128_encrypt,
      decrypt = lib.nettle_gcm_camellia128_decrypt,
      digest = lib.nettle_gcm_camellia128_digest,
      context = gcm_context.gcm_camellia128
    },
    [256] = {
      setkey = lib.nettle_gcm_camellia256_set_key,
      setiv = lib.nettle_gcm_camellia256_set_iv,
      update = lib.nettle_gcm_camellia256_update,
      encrypt = lib.nettle_gcm_camellia256_encrypt,
      decrypt = lib.nettle_gcm_camellia256_decrypt,
      digest = lib.nettle_gcm_camellia256_digest,
      context = gcm_context.gcm_camellia256
    }
  }
}
local camellia = {}
camellia.__index = camellia

function camellia.new(key, mode, iv, ad)
  local len = #key
  if len ~= 16 and len ~= 24 and len ~= 32 then
    return nil, "the Camellia supported key sizes are 128, 192, and 256 bits"
  end
  if mode then
    mode = lower(mode)
  else
    mode = "ecb"
  end
  local config = ciphers[mode]
  if not config then
    return nil, "the Camellia supported modes are ECB, and GCM"
  end
  local bits = len * 8
  local cipher = config[bits]
  local context = ffi_new(cipher.context)
  cipher.setkey(context, key)
  local iv_size = config.iv_size
  if iv_size then
    iv = iv or ""
    if #iv ~= iv_size then
      return nil, "the Camellia-" .. mode:upper() .. " supported initialization vector size is " ..
        (iv_size * 8) .. " bits"
    end
    cipher.setiv(context, iv_size, iv)
  end
  if ad and cipher.update then
    cipher.update(context, #ad, ad)
  end

  return setmetatable({
    context = context,
    cipher = cipher
  }, camellia)
end

function camellia:encrypt(src, len)
  local cipher = self.cipher
  local context = self.context
  if cipher.invert and self.inverted then
    cipher.invert(context, context)
    self.inverted = nil
  end
  len = len or #src
  if cipher.digest then
    local dst = ffi_new(types.uint8_t, len)
    cipher.encrypt(context, len, dst, src)
    cipher.digest(context, 16, types.uint8_t_16)
    return ffi_str(dst, len), ffi_str(types.uint8_t_16, 16)
  end
  local dln = ceil(len / 16) * 16
  local dst = ffi_new(types.uint8_t, dln)
  ffi_copy(dst, src, len)
  cipher.encrypt(context, dln, dst, dst)
  return ffi_str(dst, dln)
end

function camellia:decrypt(src, len)
  local cipher = self.cipher
  local context = self.context
  if cipher.invert and not self.inverted then
    cipher.invert(context, context)
    self.inverted = true
  end
  len = len or #src
  if cipher.digest then
    local dst = ffi_new(types.uint8_t, len)
    cipher.decrypt(context, len, dst, src)
    cipher.digest(context, 16, types.uint8_t_16)
    return ffi_str(dst, len), ffi_str(types.uint8_t_16, 16)
  end
  local dln = ceil(len / 16) * 16
  local dst = ffi_new(types.uint8_t, dln)
  cipher.decrypt(context, dln, dst, src)
  return ffi_str(dst, len)
end

return camellia
