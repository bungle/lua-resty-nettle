local types = require "resty.nettle.types.common"
local context = require "resty.nettle.types.md5"
local lib = require "resty.nettle.library"
local ffi = require "ffi"
local ffi_new = ffi.new
local ffi_str = ffi.string
local setmetatable = setmetatable

local md5 = setmetatable({}, {
  __call = function(_, data, len)
    local ctx = ffi_new(context)
    lib.nettle_md5_init(ctx)
    lib.nettle_md5_update(ctx, len or #data, data)
    lib.nettle_md5_digest(ctx, 16, types.uint8_t_16)
    return ffi_str(types.uint8_t_16, 16)
  end
})
md5.__index = md5

function md5.new()
  local self = setmetatable({ context = ffi_new(context) }, md5)
  lib.nettle_md5_init(self.context)
  return self
end

function md5:update(data, len)
  return lib.nettle_md5_update(self.context, len or #data, data)
end

function md5:digest()
  lib.nettle_md5_digest(self.context, 16, types.uint8_t_16)
  return ffi_str(types.uint8_t_16, 16)
end

return md5
