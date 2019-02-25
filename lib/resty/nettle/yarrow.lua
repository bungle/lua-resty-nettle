local context = require "resty.nettle.types.yarrow"
local types = require "resty.nettle.types.common"
local random = require "resty.nettle.random"
local lib = require "resty.nettle.library"
local ffi = require "ffi"
local ffi_new = ffi.new
local ffi_str = ffi.string
local rawget = rawget
local getmetatable = getmetatable
local setmetatable = setmetatable

local yarrow = { func = lib.nettle_yarrow256_random }
yarrow.__index = function(t, k)
  if k == "seeded" then
    return lib.nettle_yarrow256_is_seeded(t.context) == 1
  elseif k == "sources" then
    return lib.nettle_yarrow256_needed_sources(t.context)
  end
  return rawget(getmetatable(t), k)
end

function yarrow.context(seed)
  local ctx = ffi_new(context)
  lib.nettle_yarrow256_init(ctx, 0, nil)
  if seed ~= nil then
    if not seed then
      seed = random.bytes(32)
    end
    local len = #seed
    if len > 32 then
      return nil, "seed data length should be at least 32 bytes, but it can be larger"
    end
    lib.nettle_yarrow256_seed(ctx, len, seed)
  end
  return ctx
end

function yarrow.new(seed)
  local self = setmetatable({ context = ffi_new(context) }, yarrow)
  lib.nettle_yarrow256_init(self.context, 0, nil)
  if seed then
    self:seed(seed)
  end
  return self
end

function yarrow:seed(data)
  local len = #data
  if len < 32 then
    return nil, "seed data length should be at least 32 bytes, but it can be larger"
  end
  lib.nettle_yarrow256_seed(self.context, len, data)
end

function yarrow:fast_reseed()
  return lib.nettle_yarrow256_fast_reseed(self.context)
end

function yarrow:slow_reseed()
  return lib.nettle_yarrow256_slow_reseed(self.context)
end

function yarrow:random(length)
  local buffer = ffi_new(types.uint8_t, length)
  lib.nettle_yarrow256_random(self.context, length, buffer)
  return ffi_str(buffer, length)
end

return yarrow
