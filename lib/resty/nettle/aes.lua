require "resty.nettle.types.cbc"
require "resty.nettle.types.cfb"
require "resty.nettle.types.ctr"

local aes_context = require "resty.nettle.types.aes"
local eax_context = require "resty.nettle.types.eax"
local gcm_context = require "resty.nettle.types.gcm"
local ccm_context = require "resty.nettle.types.ccm"
local types = require "resty.nettle.types.common"
local lib = require "resty.nettle.library"
local ffi = require "ffi"
local ffi_new = ffi.new
local ffi_copy = ffi.copy
local ffi_str = ffi.string
local lower = string.lower
local ceil = math.ceil
local huge = math.huge
local type = type
local setmetatable = setmetatable

local ciphers = {
  ecb = {
    [128] = {
      setkey = lib.nettle_aes128_set_encrypt_key,
      invert = lib.nettle_aes128_invert_key,
      encrypt = lib.nettle_aes128_encrypt,
      decrypt = lib.nettle_aes128_decrypt,
      context = aes_context.aes128,
    },
    [192] = {
      setkey = lib.nettle_aes192_set_encrypt_key,
      invert = lib.nettle_aes192_invert_key,
      encrypt = lib.nettle_aes192_encrypt,
      decrypt = lib.nettle_aes192_decrypt,
      context = aes_context.aes192,
    },
    [256] = {
      setkey = lib.nettle_aes256_set_encrypt_key,
      invert = lib.nettle_aes256_invert_key,
      encrypt = lib.nettle_aes256_encrypt,
      decrypt = lib.nettle_aes256_decrypt,
      context = aes_context.aes256,
    },
  },
  cbc = {
    iv_size = 16,
    [128] = {
      setkey = lib.nettle_aes128_set_encrypt_key,
      invert = lib.nettle_aes128_invert_key,
      encrypt = lib.nettle_cbc_encrypt,
      decrypt = lib.nettle_cbc_decrypt,
      cipher = {
        encrypt = lib.nettle_aes128_encrypt,
        decrypt = lib.nettle_aes128_decrypt
      },
      context = aes_context.aes128,
    },
    [192] = {
      setkey = lib.nettle_aes192_set_encrypt_key,
      invert = lib.nettle_aes192_invert_key,
      encrypt = lib.nettle_cbc_encrypt,
      decrypt = lib.nettle_cbc_decrypt,
      cipher = {
        encrypt = lib.nettle_aes192_encrypt,
        decrypt = lib.nettle_aes192_decrypt
      },
      context = aes_context.aes192,
    },
    [256] = {
      setkey = lib.nettle_aes256_set_encrypt_key,
      invert = lib.nettle_aes256_invert_key,
      encrypt = lib.nettle_cbc_encrypt,
      decrypt = lib.nettle_cbc_decrypt,
      cipher = {
        encrypt = lib.nettle_aes256_encrypt,
        decrypt = lib.nettle_aes256_decrypt
      },
      context = aes_context.aes256,
    },
  },
  cfb = {
    iv_size = 16,
    [128] = {
      setkey = lib.nettle_aes128_set_encrypt_key,
      encrypt = lib.nettle_cfb_encrypt,
      decrypt = lib.nettle_cfb_decrypt,
      cipher = {
        encrypt = lib.nettle_aes128_encrypt,
        decrypt = lib.nettle_aes128_encrypt
      },
      context = aes_context.aes128,
    },
    [192] = {
      setkey = lib.nettle_aes192_set_encrypt_key,
      encrypt = lib.nettle_cfb_encrypt,
      decrypt = lib.nettle_cfb_decrypt,
      cipher = {
        encrypt = lib.nettle_aes192_encrypt,
        decrypt = lib.nettle_aes192_encrypt
      },
      context = aes_context.aes192,
    },
    [256] = {
      setkey = lib.nettle_aes256_set_encrypt_key,
      encrypt = lib.nettle_cfb_encrypt,
      decrypt = lib.nettle_cfb_decrypt,
      cipher = {
        encrypt = lib.nettle_aes256_encrypt,
        decrypt = lib.nettle_aes256_encrypt
      },
      context = aes_context.aes256,
    },
  },
  ctr = {
    iv_size = 16,
    [128] = {
      setkey = lib.nettle_aes128_set_encrypt_key,
      encrypt = lib.nettle_ctr_crypt,
      decrypt = lib.nettle_ctr_crypt,
      cipher = {
        encrypt = lib.nettle_aes128_encrypt,
        decrypt = lib.nettle_aes128_encrypt
      },
      context = aes_context.aes128,
    },
    [192] = {
      setkey = lib.nettle_aes192_set_encrypt_key,
      encrypt = lib.nettle_ctr_crypt,
      decrypt = lib.nettle_ctr_crypt,
      cipher = {
        encrypt = lib.nettle_aes192_encrypt,
        decrypt = lib.nettle_aes192_encrypt
      },
      context = aes_context.aes192,
    },
    [256] = {
      setkey = lib.nettle_aes256_set_encrypt_key,
      encrypt = lib.nettle_ctr_crypt,
      decrypt = lib.nettle_ctr_crypt,
      cipher = {
        encrypt = lib.nettle_aes256_encrypt,
        decrypt = lib.nettle_aes256_encrypt
      },
      context = aes_context.aes256,
    },
  },
  eax = {
    iv_size = huge,
    [128] = {
      setkey = lib.nettle_eax_aes128_set_key,
      setiv = lib.nettle_eax_aes128_set_nonce,
      update = lib.nettle_eax_aes128_update,
      encrypt = lib.nettle_eax_aes128_encrypt,
      decrypt = lib.nettle_eax_aes128_decrypt,
      digest = lib.nettle_eax_aes128_digest,
      context = eax_context.eax_aes128,
    },
  },
  gcm = {
    iv_size = 12,
    [128] = {
      setkey = lib.nettle_gcm_aes128_set_key,
      setiv = lib.nettle_gcm_aes128_set_iv,
      update = lib.nettle_gcm_aes128_update,
      encrypt = lib.nettle_gcm_aes128_encrypt,
      decrypt = lib.nettle_gcm_aes128_decrypt,
      digest = lib.nettle_gcm_aes128_digest,
      context = gcm_context.gcm_aes128,
    },
    [192] = {
      setkey = lib.nettle_gcm_aes192_set_key,
      setiv = lib.nettle_gcm_aes192_set_iv,
      update = lib.nettle_gcm_aes192_update,
      encrypt = lib.nettle_gcm_aes192_encrypt,
      decrypt = lib.nettle_gcm_aes192_decrypt,
      digest = lib.nettle_gcm_aes192_digest,
      context = gcm_context.gcm_aes192,
    },
    [256] = {
      setkey = lib.nettle_gcm_aes256_set_key,
      setiv = lib.nettle_gcm_aes256_set_iv,
      update = lib.nettle_gcm_aes256_update,
      encrypt = lib.nettle_gcm_aes256_encrypt,
      decrypt = lib.nettle_gcm_aes256_decrypt,
      digest = lib.nettle_gcm_aes256_digest,
      context = gcm_context.gcm_aes256,
    },
  },
  ccm = {
    iv_size = { 7, 14 },
    [128] = {
      setkey = lib.nettle_ccm_aes128_set_key,
      setiv = lib.nettle_ccm_aes128_set_nonce,
      update = lib.nettle_ccm_aes128_update,
      encrypt = lib.nettle_ccm_aes128_encrypt,
      decrypt = lib.nettle_ccm_aes128_decrypt,
      digest = lib.nettle_ccm_aes128_digest,
      context = ccm_context.ccm_aes128,
    },
    [192] = {
      setkey = lib.nettle_ccm_aes192_set_key,
      setiv = lib.nettle_ccm_aes192_set_nonce,
      update = lib.nettle_ccm_aes192_update,
      encrypt = lib.nettle_ccm_aes192_encrypt,
      decrypt = lib.nettle_ccm_aes192_decrypt,
      digest = lib.nettle_ccm_aes192_digest,
      context = ccm_context.ccm_aes192,
    },
    [256] = {
      setkey = lib.nettle_ccm_aes256_set_key,
      setiv = lib.nettle_ccm_aes256_set_nonce,
      update = lib.nettle_ccm_aes256_update,
      encrypt = lib.nettle_ccm_aes256_encrypt,
      decrypt = lib.nettle_ccm_aes256_decrypt,
      digest = lib.nettle_ccm_aes256_digest,
      context = ccm_context.ccm_aes256,
    },
  },
}

do
  local version = require "resty.nettle.version"
  if version.major > 3 or (version.major == 3 and version.minor > 4) then
    ciphers.cfb8 = {
      iv_size = 16,
      [128] = {
        setkey = lib.nettle_aes128_set_encrypt_key,
        encrypt = lib.nettle_cfb8_encrypt,
        decrypt = lib.nettle_cfb8_decrypt,
        cipher = {
          encrypt = lib.nettle_aes128_encrypt,
          decrypt = lib.nettle_aes128_encrypt
        },
        context = aes_context.aes128,
      },
      [192] = {
        setkey = lib.nettle_aes192_set_encrypt_key,
        encrypt = lib.nettle_cfb8_encrypt,
        decrypt = lib.nettle_cfb8_decrypt,
        cipher = {
          encrypt = lib.nettle_aes192_encrypt,
          decrypt = lib.nettle_aes192_encrypt
        },
        context = aes_context.aes192,
      },
      [256] = {
        setkey = lib.nettle_aes256_set_encrypt_key,
        encrypt = lib.nettle_cfb8_encrypt,
        decrypt = lib.nettle_cfb8_decrypt,
        cipher = {
          encrypt = lib.nettle_aes256_encrypt,
          decrypt = lib.nettle_aes256_encrypt
        },
        context = aes_context.aes256,
      },
    }
  end
end

local ccm = {}
ccm.__index = ccm

function ccm:encrypt(src, len)
  local cipher = self.cipher
  local context = self.context
  local iv = self.iv
  local ad = self.ad or ""
  local lad = #ad
  len = len or #src
  cipher.setiv(context, #iv, iv, lad, len, 16)
  if ad then cipher.update(context, lad, ad) end
  local dst = ffi_new(types.uint8_t, len)
  cipher.encrypt(context, len, dst, src)
  cipher.digest(context, 16, types.uint8_t_16)
  return ffi_str(dst, len), ffi_str(types.uint8_t_16, 16)
end

function ccm:decrypt(src, len)
  local cipher = self.cipher
  local context = self.context
  local iv = self.iv
  local ad = self.ad or ""
  local lad = #ad
  len = len or #src
  cipher.setiv(context, #iv, iv, lad, len, 16)
  if ad then cipher.update(context, lad, ad) end
  local dst = ffi_new(types.uint8_t, len)
  cipher.decrypt(context, len, dst, src)
  cipher.digest(context, 16, types.uint8_t_16)
  return ffi_str(dst, len), ffi_str(types.uint8_t_16, 16)
end

local aes = {}
aes.__index = aes

function aes.new(key, mode, iv, ad)
  local len = #key
  if len ~= 16 and len ~= 24 and len ~= 32 then
    return nil, "the AES supported key sizes are 128, 192, and 256 bits"
  end

  if mode then
    mode = lower(mode)
  else
    mode = "ecb"
  end

  local config = ciphers[mode]
  if not config then
    return nil, "the AES supported modes are ECB, CBC, CTR, EAX, GCM, CCM, and XTS"
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
      if type(iv_size) == "table" then
        if #iv < iv_size[1] or #iv > iv_size[2] then
          return nil, "the AES-" .. mode:upper() .. " supported initialization vector sizes are between " ..
            (iv_size[1] * 8) .. " and " .. (iv_size[2] * 8) .. " bits"
        end
        return setmetatable({
          context = context,
          cipher = cipher,
          iv = iv,
          ad = ad
        }, ccm)
      else
        if #iv ~= iv_size then
          return nil, "the AES-" .. mode:upper() .. " supported initialization vector size is " ..
            (iv_size * 8) .. " bits"
        end
      end
    end
    if cipher.setiv then
      cipher.setiv(context, iv_size, iv)
    else
      return setmetatable({
        context = context,
        cipher = cipher,
        iv = iv
      }, aes)
    end
  end
  if ad and cipher.update then
    cipher.update(context, #ad, ad)
  end
  return setmetatable({
    context = context,
    cipher = cipher
  }, aes)
end

function aes:encrypt(src, len)
  local cipher = self.cipher
  local context = self.context
  if cipher.invert and self.inverted then
    cipher.invert(context, context)
    self.inverted = nil
  end
  len = len or #src
  if self.iv then
    local dln = len
    if cipher.invert then dln = ceil(dln / 16) * 16 end
    local dst = ffi_new(types.uint8_t, dln)
    ffi_copy(dst, src, len)
    local ivl = #self.iv
    local iv = ffi_new(types.uint8_t, ivl)
    ffi_copy(iv, self.iv, ivl)
    cipher.encrypt(context, cipher.cipher.encrypt, 16, iv, dln, dst, dst)
    return ffi_str(dst, dln)
  elseif cipher.digest then
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

function aes:decrypt(src, len)
  local cipher = self.cipher
  local context = self.context
  if cipher.invert and not self.inverted then
    cipher.invert(context, context)
    self.inverted = true
  end
  len = len or #src
  if self.iv then
    local dln = cipher.invert and ceil(len / 16) * 16 or len
    local dst = ffi_new(types.uint8_t, dln)
    local ivl = #self.iv
    local iv = ffi_new(types.uint8_t, ivl)
    ffi_copy(iv, self.iv, ivl)
    cipher.decrypt(context, cipher.cipher.decrypt, 16, iv, dln, dst, src)
    return ffi_str(dst, len)
  elseif cipher.digest then
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

return aes
