require "resty.nettle.types.ctr"
require "resty.nettle.types.cbc"
local twofish_context = require "resty.nettle.types.twofish"
local types = require "resty.nettle.types.common"
local lib = require "resty.nettle.library"
local ffi = require "ffi"
local ffi_new = ffi.new
local ffi_copy = ffi.copy
local ffi_str = ffi.string
local lower = string.lower
local ceil = math.ceil
local huge = math.huge
local setmetatable = setmetatable

local ciphers = {
  ecb = {
    [128] = {
      setkey = lib.nettle_twofish128_set_key,
      encrypt = lib.nettle_twofish_encrypt,
      decrypt = lib.nettle_twofish_decrypt,
      context = twofish_context,
    },
    [192] = {
      setkey = lib.nettle_twofish192_set_key,
      encrypt = lib.nettle_twofish_encrypt,
      decrypt = lib.nettle_twofish_decrypt,
      context = twofish_context,
    },
    [256] = {
      setkey = lib.nettle_twofish256_set_key,
      encrypt = lib.nettle_twofish_encrypt,
      decrypt = lib.nettle_twofish_decrypt,
      context = twofish_context,
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
      },
      context = twofish_context,
    },
    [192] = {
      setkey = lib.nettle_twofish192_set_key,
      encrypt = lib.nettle_cbc_encrypt,
      decrypt = lib.nettle_cbc_decrypt,
      padding = true,
      cipher = {
        encrypt = lib.nettle_twofish_encrypt,
        decrypt = lib.nettle_twofish_decrypt
      },
      context = twofish_context,
    },
    [256] = {
      setkey = lib.nettle_twofish256_set_key,
      encrypt = lib.nettle_cbc_encrypt,
      decrypt = lib.nettle_cbc_decrypt,
      padding = true,
      cipher = {
        encrypt = lib.nettle_twofish_encrypt,
        decrypt = lib.nettle_twofish_decrypt
      },
      context = twofish_context,
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
      },
      context = twofish_context,
    },
    [192] = {
      setkey = lib.nettle_twofish192_set_key,
      encrypt = lib.nettle_ctr_crypt,
      decrypt = lib.nettle_ctr_crypt,
      cipher = {
        encrypt = lib.nettle_twofish_encrypt,
        decrypt = lib.nettle_twofish_encrypt
      },
      context = twofish_context,
    },
    [256] = {
      setkey = lib.nettle_twofish256_set_key,
      encrypt = lib.nettle_ctr_crypt,
      decrypt = lib.nettle_ctr_crypt,
      cipher = {
        encrypt = lib.nettle_twofish_encrypt,
        decrypt = lib.nettle_twofish_encrypt
      },
      context = twofish_context,
    }
  },
}

local twofish = {}
twofish.__index = twofish

function twofish.new(key, mode, iv, ad)
  if mode then
    mode = lower(mode)
  else
    mode = "ecb"
  end
  local len = #key
  if len ~= 16 and len ~= 24 and len ~= 32 then
    return nil, "the TWOFISH supported key sizes are 128, 192, and 256 bits"
  end
  local config = ciphers[mode]
  if not config then
    return nil, "the TWOFISH supported modes are ECB, CBC, and CTR"
  end
  local bits = len * 8
  local cipher = config[bits]
  local context = ffi_new(cipher.context)
  cipher.setkey(context, key)
  local iv_size = config.iv_size
  if iv_size then
    iv = iv or ""
    if iv_size == huge then
      iv_size = #iv
    else
      if #iv ~= iv_size then
        return nil, "the TWOFISH-" .. mode:upper() .. " supported initialization vector size is " ..
          (iv_size * 8) .. " bits"
      end
    end
    if cipher.setiv then
      cipher.setiv(context, iv_size, iv)
      iv = nil
    end
  end
  if ad and cipher.update then
    cipher.update(context, #ad, ad)
    ad = nil
  end
  return setmetatable({
    context = context,
    cipher = cipher,
    iv = iv,
    ad = ad,
  }, twofish)
end

function twofish:encrypt(src, len)
  local cipher = self.cipher
  local context = self.context
  len = len or #src
  if self.iv then
    local dln = len
    if cipher.padding then
      dln = ceil(dln / 16) * 16
    end
    local ivl = #self.iv
    local dst, iv
    if dln == len then
      dst, iv = types.buffers(dln, ivl)
    else
      dst = types.zerobuffers(dln)
      iv  = types.buffers(ivl)
    end
    ffi_copy(dst, src, len)
    ffi_copy(iv, self.iv, ivl)
    cipher.encrypt(context, cipher.cipher.encrypt, ivl, iv, dln, dst, dst)
    return ffi_str(dst, dln)
  end
  local dln = ceil(len / 16) * 16
  local dst
  if dln == len then
    dst = types.buffers(dln)
  else
    dst = types.zerobuffers(dln)
  end
  ffi_copy(dst, src, len)
  cipher.encrypt(context, dln, dst, dst)
  return ffi_str(dst, dln)
end

function twofish:decrypt(src, len)
  local cipher = self.cipher
  local context = self.context
  len = len or #src
  if self.iv then
    local ivl = #self.iv
    local dst, iv = types.buffers(len, ivl)
    ffi_copy(iv, self.iv, ivl)
    cipher.decrypt(context, cipher.cipher.decrypt, ivl, iv, len, dst, src)
    return ffi_str(dst, len)
  end
  local dln = ceil(len / 16) * 16
  local dst
  if dln == len then
    dst = types.buffers(dln)
  else
    dst = types.zerobuffers(dln)
  end
  cipher.decrypt(context, dln, dst, src)
  return ffi_str(dst, len)
end

return twofish
