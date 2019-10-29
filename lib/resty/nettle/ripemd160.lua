local types = require "resty.nettle.types.common"
local context = require "resty.nettle.types.ripemd160"
local lib = require "resty.nettle.library"
local ffi = require "ffi"
local ffi_new = ffi.new
local ffi_str = ffi.string
local setmetatable = setmetatable

local ripemd160 = setmetatable({}, {
  __call = function(_, data, len)
    local ctx = ffi_new(context)
    lib.nettle_ripemd160_init(ctx)
    lib.nettle_ripemd160_update(ctx, len or #data, data)
    lib.nettle_ripemd160_digest(ctx, 20, types.uint8_t_20)
    return ffi_str(types.uint8_t_20, 20)
  end
})
ripemd160.__index = ripemd160

function ripemd160.new()
  local self = setmetatable({ context = ffi_new(context) }, ripemd160)
  lib.nettle_ripemd160_init(self.context)
  return self
end

function ripemd160:update(data, len)
  return lib.nettle_ripemd160_update(self.context, len or #data, data)
end

function ripemd160:digest()
  lib.nettle_ripemd160_digest(self.context, 20, types.uint8_t_20)
  return ffi_str(types.uint8_t_20, 20)
end

return ripemd160
