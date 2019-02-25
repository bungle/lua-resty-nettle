local types = require "resty.nettle.types.common"
local context = require "resty.nettle.types.knuth-lfib"
local lib = require "resty.nettle.library"
local ffi = require "ffi"
local ffi_new = ffi.new
local ffi_str = ffi.string
local setmetatable = setmetatable

local knuth = { func = lib.nettle_knuth_lfib_random }
knuth.__index = knuth

function knuth.context(seed)
  local ctx = ffi_new(context)
  lib.nettle_knuth_lfib_init(ctx, seed or 0)
  return ctx
end

function knuth.new(seed)
  local self = setmetatable({ context = ffi_new(context) }, knuth)
  lib.nettle_knuth_lfib_init(self.context, seed or 0)
  return self
end

function knuth:number()
  return lib.nettle_knuth_lfib_get(self.context)
end

function knuth:array(n)
  local b = ffi_new(types.uint32_t, n)
  lib.nettle_knuth_lfib_get_array(self.context, n, b)
  local r = {}
  for i = 1, n do r[i] = b[i - 1] end
  return r
end

function knuth:random(n)
  local b = ffi_new(types.uint8_t, n)
  lib.nettle_knuth_lfib_random(self.context, n, b)
  return ffi_str(b, n)
end

return knuth
