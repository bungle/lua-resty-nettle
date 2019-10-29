require "resty.nettle.types.ctr"
require "resty.nettle.types.cbc"
local context = require "resty.nettle.types.twofish"
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
      setkey = lib.nettle_twofish128_set_key,
      encrypt = lib.nettle_twofish_encrypt,
      decrypt = lib.nettle_twofish_decrypt
    },
    [192] = {
      setkey = lib.nettle_twofish192_set_key,
      encrypt = lib.nettle_twofish_encrypt,
      decrypt = lib.nettle_twofish_decrypt
    },
    [256] = {
      setkey = lib.nettle_twofish256_set_key,
      encrypt = lib.nettle_twofish_encrypt,
      decrypt = lib.nettle_twofish_decrypt
    }
  },
  cbc = {
    iv_size = 16,
    [128] = {
      setkey = lib.nettle_twofish128_set_key,
      encrypt = lib.nettle_cbc_encrypt,
      decrypt = lib.nettle_cbc_decrypt,
      padding = true,
      cipher = {
        encrypt = lib.nettle_twofish_encrypt,
        decrypt = lib.nettle_twofish_decrypt
      }
    },
    [192] = {
      setkey = lib.nettle_twofish192_set_key,
      encrypt = lib.nettle_cbc_encrypt,
      decrypt = lib.nettle_cbc_decrypt,
      padding = true,
      cipher = {
        encrypt = lib.nettle_twofish_encrypt,
        decrypt = lib.nettle_twofish_decrypt
      }
    },
    [256] = {
      setkey = lib.nettle_twofish256_set_key,
      encrypt = lib.nettle_cbc_encrypt,
      decrypt = lib.nettle_cbc_decrypt,
      padding = true,
      cipher = {
        encrypt = lib.nettle_twofish_encrypt,
        decrypt = lib.nettle_twofish_decrypt
      }
    }
  },
  ctr = {
    iv_size = 16,
    [128] = {
      setkey = lib.nettle_twofish128_set_key,
      encrypt = lib.nettle_ctr_crypt,
      decrypt = lib.nettle_ctr_crypt,
      cipher = {
        encrypt = lib.nettle_twofish_encrypt,
        decrypt = lib.nettle_twofish_encrypt
      }
    },
    [192] = {
      setkey = lib.nettle_twofish192_set_key,
      encrypt = lib.nettle_ctr_crypt,
      decrypt = lib.nettle_ctr_crypt,
      cipher = {
        encrypt = lib.nettle_twofish_encrypt,
        decrypt = lib.nettle_twofish_encrypt
      }
    },
    [256] = {
      setkey = lib.nettle_twofish256_set_key,
      encrypt = lib.nettle_ctr_crypt,
      decrypt = lib.nettle_ctr_crypt,
      cipher = {
        encrypt = lib.nettle_twofish_encrypt,
        decrypt = lib.nettle_twofish_encrypt
      }
    }
  },
  gcm = {
    iv_size = 12,
    [128] = {
      setkey = lib.nettle_gcm_set_key,
      setiv = lib.nettle_gcm_set_iv,
      update = lib.nettle_gcm_update,
      encrypt = lib.nettle_gcm_encrypt,
      decrypt = lib.nettle_gcm_decrypt,
      digest = lib.nettle_gcm_digest,
      key = gcm_context.key,
      context = gcm_context.gcm,
      cipher = {
        setkey = lib.nettle_twofish128_set_key,
        encrypt = lib.nettle_twofish_encrypt,
        decrypt = lib.nettle_twofish_decrypt
      }
    },
    [192] = {
      setkey = lib.nettle_gcm_set_key,
      setiv = lib.nettle_gcm_set_iv,
      update = lib.nettle_gcm_update,
      encrypt = lib.nettle_gcm_encrypt,
      decrypt = lib.nettle_gcm_decrypt,
      digest = lib.nettle_gcm_digest,
      key = gcm_context.key,
      context = gcm_context.gcm,
      cipher = {
        setkey = lib.nettle_twofish192_set_key,
        encrypt = lib.nettle_twofish_encrypt,
        decrypt = lib.nettle_twofish_decrypt
      }
    },
    [256] = {
      setkey = lib.nettle_gcm_set_key,
      setiv = lib.nettle_gcm_set_iv,
      update = lib.nettle_gcm_update,
      encrypt = lib.nettle_gcm_encrypt,
      decrypt = lib.nettle_gcm_decrypt,
      digest = lib.nettle_gcm_digest,
      key = gcm_context.key,
      context = gcm_context.gcm,
      cipher = {
        setkey = lib.nettle_twofish256_set_key,
        encrypt = lib.nettle_twofish_encrypt,
        decrypt = lib.nettle_twofish_decrypt
      }
    }
  }
}

local twofish = {}
twofish.__index = twofish

function twofish.new(key, mode, iv, _)
  local len = #key
  if len ~= 16 and len ~= 24 and len ~= 32 then
    return nil, "the TWOFISH supported key sizes are 128, 192, and 256 bits"
  end

  if mode then
    mode = lower(mode)
  else
    mode = "ecb"
  end

  local config = ciphers[mode]
  if not config then
    return nil, "the TWOFISH supported modes are ECB, CBC, and CTR"
  end
  local bits = len * 8
  local cip = config[bits]
  local ctx = ffi_new(context)
  cip.setkey(ctx, key)
  local iv_size = config.iv_size
  if iv_size then
    iv = iv or ""
    if #iv ~= iv_size then
      return "the TWOFISH-" .. mode:upper() .. " supported initialization vector size is " .. (iv_size * 8) ..
        " bits"
    end
  end
  return setmetatable({
    context = ctx,
    cipher = cip,
    iv = iv
  }, twofish)
end

function twofish:encrypt(src, len)
  local cip = self.cipher
  local ctx = self.context
  len = len or #src
  if self.iv then
    local dln = len
    if cip.padding then dln = ceil(dln / 16) * 16 end
    local dst = ffi_new(types.uint8_t, dln)
    ffi_copy(dst, src, len)
    local ivl = #self.iv
    local iv = ffi_new(types.uint8_t, ivl)
    ffi_copy(iv, self.iv, ivl)
    cip.encrypt(ctx, cip.cipher.encrypt, 16, iv, dln, dst, dst)
    return ffi_str(dst, dln)
  end
  local dln = ceil(len / 16) * 16
  local dst = ffi_new(types.uint8_t, dln)
  ffi_copy(dst, src, len)
  cip.encrypt(ctx, dln, dst, dst)
  return ffi_str(dst, dln)
end

function twofish:decrypt(src, len)
  local cip = self.cipher
  local ctx = self.context
  len = len or #src
  if self.iv then
    local dst = ffi_new(types.uint8_t, len)
    local ivl = #self.iv
    local iv = ffi_new(types.uint8_t, ivl)
    ffi_copy(iv, self.iv, ivl)
    cip.decrypt(ctx, cip.cipher.decrypt, 16, iv, len, dst, src)
    return ffi_str(dst, len)
  end
  local dln = ceil(len / 16) * 16
  local dst = ffi_new(types.uint8_t, dln)
  cip.decrypt(ctx, dln, dst, src)
  return ffi_str(dst, len)
end

return twofish
