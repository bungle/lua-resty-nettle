local types = require "resty.nettle.types.common"
local context = require "resty.nettle.types.des"
local lib = require "resty.nettle.library"
local ffi = require "ffi"
local ffi_new = ffi.new
local ffi_copy = ffi.copy
local ffi_str = ffi.string
local lower = string.lower
local ceil = math.ceil
local setmetatable = setmetatable

local des = {}
des.__index = des

local ciphers = {
  des = {
    ecb = {
      context = context.des,
      setkey = lib.nettle_des_set_key,
      encrypt = lib.nettle_des_encrypt,
      decrypt = lib.nettle_des_decrypt
    },
    cbc = {
      iv_size = 8,
      context = context.des,
      setkey = lib.nettle_des_set_key,
      encrypt = lib.nettle_cbc_encrypt,
      decrypt = lib.nettle_cbc_decrypt,
      cipher = {
        encrypt = lib.nettle_des_encrypt,
        decrypt = lib.nettle_des_decrypt
      }
    },
    ctr = {
      iv_size = 8,
      context = context.des,
      setkey = lib.nettle_des_set_key,
      encrypt = lib.nettle_ctr_crypt,
      decrypt = lib.nettle_ctr_crypt,
      cipher = {
        encrypt = lib.nettle_des_encrypt,
        decrypt = lib.nettle_des_encrypt
      }
    }
  },
  des3 = {
    ecb = {
      context = context.des3,
      setkey = lib.nettle_des3_set_key,
      encrypt = lib.nettle_des3_encrypt,
      decrypt = lib.nettle_des3_decrypt
    },
    cbc = {
      iv_size = 8,
      context = context.des3,
      setkey = lib.nettle_des3_set_key,
      encrypt = lib.nettle_cbc_encrypt,
      decrypt = lib.nettle_cbc_decrypt,
      cipher = {
        encrypt = lib.nettle_des3_encrypt,
        decrypt = lib.nettle_des3_decrypt
      }
    },
    ctr = {
      iv_size = 8,
      context = context.des3,
      setkey = lib.nettle_des3_set_key,
      encrypt = lib.nettle_ctr_crypt,
      decrypt = lib.nettle_ctr_crypt,
      cipher = {
        encrypt = lib.nettle_des3_encrypt,
        decrypt = lib.nettle_des3_encrypt
      }
    }
  }
}

function des.new(key, mode, iv)
  local len = #key
  if len ~= 8 and len ~= 24 then
    return nil, "the DES supported key size is 64 bits, and DES3 supported key size is 192 bits"
  end
  local cipher
  if len == 8 then
    cipher = ciphers.des
  else
    cipher = ciphers.des3
  end
  if mode then
    mode = lower(mode)
  else
    mode = "ecb"
  end
  cipher = cipher[mode]
  if not cipher then
    return nil, "the DES/DES3 supported modes are currently ECB, CBC, and CTR"
  end
  local iv_size = cipher.iv_size
  if iv_size then
    if #iv ~= iv_size then
      return nil, "the DES-/DES3-" .. mode:upper() .. " supported initialization vector size is " ..
        (iv_size * 8) .. " bits"
    end
  end
  local ct = ffi_new(cipher.context)
  local wk = cipher.setkey(ct, key)
  return setmetatable({ context = ct, cipher = cipher, iv = iv }, des), wk ~= 1
end

function des.check_parity(key)
  local len = #key
  if len ~= 8 and len ~= 24 then
    return nil, "the DES supported key size is 64 bits, and DES3 supported key size is 192 bits"
  end
  return lib.nettle_des_check_parity(len, key) == 1
end

function des.fix_parity(src)
  local len = #src
  if len ~= 8 and len ~= 24 then
    return nil, "the DES supported key size is 64 bits, and DES3 supported key size is 192 bits"
  end
  local dst = ffi_new(types.uint8_t, len)
  lib.nettle_des_fix_parity(len, dst, src)
  return ffi_str(dst, len)
end

function des:encrypt(src, len)
  len = len or #src
  local cip = self.cipher
  local ctx = self.context
  local dln = ceil(len / 8) * 8
  local dst = ffi_new(types.uint8_t, dln)
  ffi_copy(dst, src, len)
  if self.iv then
    ffi_copy(types.uint8_t_8, self.iv, 8)
    cip.encrypt(ctx, cip.cipher.encrypt, 8, types.uint8_t_8, dln, dst, dst)
  else
    cip.encrypt(ctx, dln, dst, dst)
  end
  return ffi_str(dst, dln)
end

function des:decrypt(src, len)
  local cip = self.cipher
  local ctx = self.context
  len = len or #src
  local dln = ceil(len / 8) * 8
  local dst = ffi_new(types.uint8_t, dln)
  if self.iv then
    ffi_copy(types.uint8_t_8, self.iv, 8)
    cip.decrypt(ctx, cip.cipher.decrypt, 8, types.uint8_t_8, dln, dst, src)
  else
    cip.decrypt(ctx, dln, dst, src)
  end
  return ffi_str(dst, len)
end

return des
