do
  local version = require "resty.nettle.version"
  if version.major < 3 or (version.major == 3 and version.minor < 5) then
    return nil, string.format("CMAC is not supportted with Nettle %s", version)
  end
end

local types = require "resty.nettle.types.common"
local context = require "resty.nettle.types.cmac"
local lib = require "resty.nettle.library"
local ffi = require "ffi"
local ffi_new = ffi.new
local ffi_str = ffi.string
local setmetatable = setmetatable

local cmacs = {
  aes128 = {
    context = context.aes128,
    buffer = types.uint8_t_16,
    setkey = lib.nettle_cmac_aes128_set_key,
    update = lib.nettle_cmac_aes128_update,
    digest = lib.nettle_cmac_aes128_digest,
  },
  aes256 = {
    context = context.aes256,
    buffer = types.uint8_t_16,
    setkey = lib.nettle_cmac_aes256_set_key,
    update = lib.nettle_cmac_aes256_update,
    digest = lib.nettle_cmac_aes256_digest,
  },
}

cmacs[128] = cmacs.aes128
cmacs[256] = cmacs.aes256

local cmac = {}
cmac.__index = cmac

function cmac:update(data, len)
  return self.cmac.update(self.context, len or #data, data)
end

function cmac:digest()
  local cmc = self.cmac
  cmc.digest(self.context, 16, cmc.buffer)
  return ffi_str(cmac.buffer, 16)
end

local function factory(mac)
  return setmetatable({
    new = function(key)
      local ctx = ffi_new(mac.context)
      mac.setkey(ctx, key)
      return setmetatable({ context = ctx, cmac = mac }, cmac)
    end
  }, {
    __call = function(_, key, data, len)
      local ctx = ffi_new(mac.context)
      mac.setkey(ctx, key)
      mac.update(ctx, len or #data, data)
      mac.digest(ctx, 16, mac.buffer)
      return ffi_str(mac.buffer, 16)
    end
  })
end

return setmetatable({
  aes128 = factory(cmacs.aes128),
  aes256 = factory(cmacs.aes256)
}, {
  __call = function(_, cipher, key, data, len)
    local mac = cmacs[cipher]
    if not mac then
      return nil, "the supported cmac ciphers are aes128 and aes256"
    end
    local ctx = ffi_new(mac.context)
    mac.setkey(ctx, key)
    mac.update(ctx, len or #data, data)
    mac.digest(ctx, 16, mac.buffer)
    return ffi_str(mac.buffer, 16)
  end
})
