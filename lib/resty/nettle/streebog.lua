local types = require "resty.nettle.types.common"
local context = require "resty.nettle.types.streebog"
local lib = require "resty.nettle.library"
local ffi = require "ffi"
local ffi_new = ffi.new
local ffi_str = ffi.string
local lower = string.lower
local setmetatable = setmetatable

local hashes = {
  streebog256 = {
    length = 32,
    context = context,
    buffer = types.uint8_t_32,
    init = lib.nettle_streebog256_init,
    update = lib.nettle_streebog512_update,
    digest = lib.nettle_streebog256_digest,
  },
  streebog512 = {
    length = 64,
    context = context,
    buffer = types.uint8_t_64,
    init = lib.nettle_streebog512_init,
    update = lib.nettle_streebog512_update,
    digest = lib.nettle_streebog512_digest,
  },
}

local streebog = {}
streebog.__index = streebog

function streebog:update(data, len)
  return self.hash.update(self.context, len or #data, data)
end

function streebog:digest()
  local hash = self.hash
  hash.digest(self.context, hash.length, hash.buffer)
  return ffi_str(hash.buffer, hash.length)
end

local function factory(hash)
  return setmetatable({
    new = function()
      local ctx = ffi_new(hash.context)
      hash.init(ctx)
      return setmetatable({ context = ctx, hash = hash }, streebog)
    end
  }, {
    __call = function(_, data, len)
      local ctx = ffi_new(hash.context)
      hash.init(ctx)
      hash.update(ctx, len or #data, data)
      hash.digest(ctx, hash.length, hash.buffer)
      return ffi_str(hash.buffer, hash.length)
    end
  })
end

return setmetatable({
  streebog256 = factory(hashes.streebog256),
  streebog512 = factory(hashes.streebog512),
}, {
  __call = function(_, algorithm, data, len)
    local hash = hashes[lower(algorithm)]
    if not hash then
      return nil, "the supported Streebog algorithms are Streebog256, and Streebog512"
    end
    local ctx = ffi_new(hash.context)
    hash.init(ctx)
    hash.update(ctx, len or #data, data)
    hash.digest(ctx, hash.length, hash.buffer)
    return ffi_str(hash.buffer, hash.length)
  end
})
