local types = require "resty.nettle.types.common"
local context = require "resty.nettle.types.md4"
local lib = require "resty.nettle.library"
local ffi = require "ffi"
local ffi_new = ffi.new
local ffi_str = ffi.string
local setmetatable = setmetatable

local md4 = setmetatable({}, {
  __call = function(_, data, len)
    local ctx = ffi_new(context)
    lib.nettle_md4_init(ctx)
    lib.nettle_md4_update(ctx, len or #data, data)
    lib.nettle_md4_digest(ctx, 16, types.uint8_t_16)
    return ffi_str(types.uint8_t_16, 16)
  end
})
md4.__index = md4

function md4.new()
  local self = setmetatable({ context = ffi_new(context) }, md4)
  lib.nettle_md4_init(self.context)
  return self
end

function md4:update(data, len)
  return lib.nettle_md4_update(self.context, len or #data, data)
end

function md4:digest()
  lib.nettle_md4_digest(self.context, 16, types.uint8_t_16)
  return ffi_str(types.uint8_t_16, 16)
end

return md4
