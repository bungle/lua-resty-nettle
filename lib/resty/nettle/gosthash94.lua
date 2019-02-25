local types = require "resty.nettle.types.common"
local context = require "resty.nettle.types.gosthash94"
local lib = require "resty.nettle.library"
local ffi = require "ffi"
local ffi_new = ffi.new
local ffi_str = ffi.string
local setmetatable = setmetatable

local gosthash94 = setmetatable({}, {
  __call = function(_, data, len)
    local ctx = ffi_new(context)
    lib.nettle_gosthash94_init(ctx)
    lib.nettle_gosthash94_update(ctx, len or #data, data)
    lib.nettle_gosthash94_digest(ctx, 32, types.uint8_t_32)
    return ffi_str(types.uint8_t_32, 32)
  end
})
gosthash94.__index = gosthash94

function gosthash94.new()
  local self = setmetatable({ context = ffi_new(context) }, gosthash94)
  lib.nettle_gosthash94_init(self.context)
  return self
end

function gosthash94:update(data, len)
  return lib.nettle_gosthash94_update(self.context, len or #data, data)
end

function gosthash94:digest()
  lib.nettle_gosthash94_digest(self.context, 32, types.uint8_t_32)
  return ffi_str(types.uint8_t_32, 32)
end

return gosthash94
