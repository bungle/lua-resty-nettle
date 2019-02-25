local types = require "resty.nettle.types.common"
local context = require "resty.nettle.types.poly1305"
local lib = require "resty.nettle.library"
local ffi = require "ffi"
local ffi_new = ffi.new
local ffi_str = ffi.string
local setmetatable = setmetatable

local poly1305 = setmetatable({}, {
  __call = function(_, key, nonce, data, len)
    local ctx = ffi_new(context.poly1395_aes)
    lib.nettle_poly1305_aes_set_key(ctx, key)
    if nonce then
      lib.nettle_poly1305_aes_set_nonce(ctx, #nonce, nonce)
    end
    lib.nettle_poly1305_aes_update(ctx, len or #data, data)
    lib.nettle_poly1305_aes_digest(ctx, 16, types.uint8_t_16)
    return ffi_str(types.uint8_t_16, 16)
  end
})
poly1305.__index = poly1305

function poly1305.new(key, nonce)
  local self = setmetatable({ context = ffi_new(context.poly1395_aes) }, poly1305)
  lib.nettle_poly1305_aes_set_key(self.context, key)
  if nonce then
    lib.nettle_poly1305_aes_set_nonce(self.context, #nonce, nonce)
  end
  return self
end

function poly1305:update(data, len)
  return lib.nettle_poly1305_aes_update(self.context, len or #data, data)
end

function poly1305:digest()
  lib.nettle_poly1305_aes_digest(self.context, 16, types.uint8_t_16)
  return ffi_str(types.uint8_t_16, 16)
end

return poly1305
