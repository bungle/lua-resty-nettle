local types = require "resty.nettle.types.common"
local context = require "resty.nettle.types.umac"
local lib = require "resty.nettle.library"
local ffi = require "ffi"
local ffi_new = ffi.new
local ffi_str = ffi.string
local setmetatable = setmetatable

local umacs = {
  umac32 = {
    length = 4,
    context = context.umac32,
    buffer = types.uint8_t_4,
    setkey = lib.nettle_umac32_set_key,
    setnonce = lib.nettle_umac32_set_nonce,
    update = lib.nettle_umac32_update,
    digest = lib.nettle_umac32_digest
  },
  umac64 = {
    length = 8,
    context = context.umac64,
    buffer = types.uint8_t_8,
    setkey = lib.nettle_umac64_set_key,
    setnonce = lib.nettle_umac64_set_nonce,
    update = lib.nettle_umac64_update,
    digest = lib.nettle_umac64_digest
  },
  umac96 = {
    length = 12,
    context = context.umac96,
    buffer = types.uint8_t_12,
    setkey = lib.nettle_umac96_set_key,
    setnonce = lib.nettle_umac96_set_nonce,
    update = lib.nettle_umac96_update,
    digest = lib.nettle_umac96_digest
  },
  umac128 = {
    length = 16,
    context = context.umac128,
    buffer = types.uint8_t_16,
    setkey = lib.nettle_umac128_set_key,
    setnonce = lib.nettle_umac128_set_nonce,
    update = lib.nettle_umac128_update,
    digest = lib.nettle_umac128_digest
  },
}

umacs[32] = umacs.umac32
umacs[64] = umacs.umac64
umacs[96] = umacs.umac96
umacs[128] = umacs.umac128

local umac = {}
umac.__index = umac

function umac:update(data, len)
  return self.umac.update(self.context, len or #data, data)
end

function umac:digest()
  local umc = self.umac
  umc.digest(self.context, umc.length, umc.buffer)
  return ffi_str(umc.buffer, umc.length)
end

local function factory(mac)
  return setmetatable({
    new = function(key, nonce)
      local ctx = ffi_new(mac.context)
      mac.setkey(ctx, key)
      if nonce then
        mac.setnonce(ctx, #nonce, nonce)
      end
      return setmetatable({ context = ctx, umac = mac }, umac)
    end
  }, {
    __call = function(_, key, nonce, data, len)
      local ctx = ffi_new(mac.context)
      mac.setkey(ctx, key)
      if nonce then
        mac.setnonce(ctx, #nonce, nonce)
      end
      mac.update(ctx, len or #data, data)
      mac.digest(ctx, mac.length, mac.buffer)
      return ffi_str(mac.buffer, mac.length)
    end
  })
end

return setmetatable({
  umac32 = factory(umacs[32]),
  umac64 = factory(umacs[64]),
  umac96 = factory(umacs[96]),
  umac128 = factory(umacs[128])
}, {
  __call = function(_, bits, key, nonce, data, len)
    local mac = umacs[bits]
    if not mac then
      return nil, "the supported UMAC algorithm output sizes are 32, 64, 96, and 128 bits"
    end
    local ctx = ffi_new(mac.context)
    mac.setkey(ctx, key)
    if nonce then
      mac.setnonce(ctx, #nonce, nonce)
    end
    mac.update(ctx, len or #data, data)
    mac.digest(ctx, mac.length, mac.buffer)
    return ffi_str(mac.buffer, mac.length)
  end
})
