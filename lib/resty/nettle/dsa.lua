local mpz = require "resty.nettle.mpz"
local context = require "resty.nettle.types.dsa"
local hogweed = require "resty.nettle.hogweed"
local ffi = require "ffi"
local ffi_gc = ffi.gc
local ffi_new = ffi.new
local setmetatable = setmetatable

local signature = {}

signature.__index = signature

function signature.new(r, s)
  local ctx = ffi_gc(ffi_new(context.signature), hogweed.nettle_dsa_signature_clear)
  hogweed.nettle_dsa_signature_init(ctx)
  if r then
    local ok, err = mpz.set(ctx.r, r)
    if not ok then
      return nil, err
    end
  end

  if s then
    local ok, err = mpz.set(ctx.s, s)
    if not ok then
      return nil, err
    end
  end

  return setmetatable({ context = ctx }, signature)
end

function signature:r(len)
  return mpz.tostring(self.context.r, len)
end

function signature:s(len)
  return mpz.tostring(self.context.s, len)
end

local dsa = { signature = signature }
dsa.__index = dsa

return dsa
