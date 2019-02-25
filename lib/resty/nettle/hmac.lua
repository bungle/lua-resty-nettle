local types = require "resty.nettle.types.common"
local context = require "resty.nettle.types.hmac"
local lib = require "resty.nettle.library"
local ffi = require "ffi"
local ffi_new = ffi.new
local ffi_str = ffi.string
local lower = string.lower
local setmetatable = setmetatable

local hmacs = {
  md5 = {
    length = 16,
    context = context.md5,
    buffer = types.uint8_t_16,
    setkey = lib.nettle_hmac_md5_set_key,
    update = lib.nettle_hmac_md5_update,
    digest = lib.nettle_hmac_md5_digest,
  },
  ripemd160 = {
    length = 20,
    context = context.ripemd160,
    buffer = types.uint8_t_20,
    setkey = lib.nettle_hmac_ripemd160_set_key,
    update = lib.nettle_hmac_ripemd160_update,
    digest = lib.nettle_hmac_ripemd160_digest,
  },
  sha1 = {
    length = 20,
    context = context.sha1,
    buffer = types.uint8_t_20,
    setkey = lib.nettle_hmac_sha1_set_key,
    update = lib.nettle_hmac_sha1_update,
    digest = lib.nettle_hmac_sha1_digest,
  },
  sha224 = {
    length = 28,
    context = context.sha224,
    buffer = types.uint8_t_28,
    setkey = lib.nettle_hmac_sha224_set_key,
    update = lib.nettle_hmac_sha256_update,
    digest = lib.nettle_hmac_sha224_digest,
  },
  sha256 = {
    length = 32,
    context = context.sha256,
    buffer = types.uint8_t_32,
    setkey = lib.nettle_hmac_sha256_set_key,
    update = lib.nettle_hmac_sha256_update,
    digest = lib.nettle_hmac_sha256_digest,
  },
  sha384 = {
    length = 48,
    context = context.sha384,
    buffer = types.uint8_t_48,
    setkey = lib.nettle_hmac_sha384_set_key,
    update = lib.nettle_hmac_sha512_update,
    digest = lib.nettle_hmac_sha384_digest,
  },
  sha512 = {
    length = 64,
    context = context.sha512,
    buffer = types.uint8_t_64,
    setkey = lib.nettle_hmac_sha512_set_key,
    update = lib.nettle_hmac_sha512_update,
    digest = lib.nettle_hmac_sha512_digest,
  },
}

local hmac = {}
hmac.__index = hmac

function hmac:update(data, len)
  return self.hmac.update(self.context, len or #data, data)
end

function hmac:digest()
  local hmc = self.hmac
  hmc.digest(self.context, hmc.length, hmc.buffer)
  return ffi_str(hmc.buffer, hmc.length)
end

local function factory(mac)
  return setmetatable({
    new = function(key)
      local ctx = ffi_new(mac.context)
      mac.setkey(ctx, #key, key)
      return setmetatable({ context = ctx, hmac = mac }, hmac)
    end
  }, {
    __call = function(_, key, data, len)
      local ctx = ffi_new(mac.context)
      mac.setkey(ctx, #key, key)
      mac.update(ctx, len or #data, data)
      mac.digest(ctx, mac.length, mac.buffer)
      return ffi_str(mac.buffer, mac.length)
    end
  })
end

return setmetatable({
  md5 = factory(hmacs.md5),
  ripemd160 = factory(hmacs.ripemd160),
  sha1 = factory(hmacs.sha1),
  sha224 = factory(hmacs.sha224),
  sha256 = factory(hmacs.sha256),
  sha384 = factory(hmacs.sha384),
  sha512 = factory(hmacs.sha512),
}, {
  __call = function(_, algorithm, key, data, len)
    local mac = hmacs[lower(algorithm)]
    if not mac then
      return nil, "the supported HMAC algorithms are MD5, SHA1, SHA224, SHA256, SHA384, SHA512, and RIPEMD160"
    end
    local ctx = ffi_new(mac.context)
    mac.setkey(ctx, #key, key)
    mac.update(ctx, len or #data, data)
    mac.digest(ctx, mac.length, mac.buffer)
    return ffi_str(mac.buffer, mac.length)
  end
})
