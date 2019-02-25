local context = require "resty.nettle.types.ecc"
local hogweed = require "resty.nettle.hogweed"
local mpz = require "resty.nettle.mpz"
local ffi = require "ffi"
local ffi_gc = ffi.gc
local ffi_new = ffi.new
local setmetatable = setmetatable
local type = type

local mpz_t_1 = mpz.new()
local mpz_t_2 = mpz.new()

local curves = {}

do
  local pcall = pcall

  local function curve(name)
    local o, c = pcall(function()
      return hogweed[name]()
    end)
    if o then
      return c
    end
  end

  curves["P-192"] = curve("nettle_get_secp_192r1")
  curves["P-224"] = curve("nettle_get_secp_224r1")
  curves["P-256"] = curve("nettle_get_secp_256r1")
  curves["P-384"] = curve("nettle_get_secp_384r1")
  curves["P-521"] = curve("nettle_get_secp_521r1")
end

local curve = {}

curve.__index = curve

local point = {}

point.__index = point

function point.new(c, x, y)
  local ctx = ffi_gc(ffi_new(context.point), hogweed.nettle_ecc_point_clear)

  c = c or curves["P-256"]

  if type(c) == "cdata" then
    hogweed.nettle_ecc_point_init(ctx, c)
  elseif curves[c] then
    hogweed.nettle_ecc_point_init(ctx, curves[c])
  else
    return nil, "invalid curve for ECC point"
  end

  if x and y then
    mpz.set(mpz_t_1, x)
    mpz.set(mpz_t_2, y)
    if hogweed.nettle_ecc_point_set(ctx, mpz_t_1, mpz_t_2) ~= 1 then
      return nil, "unable to set ECC point"
    end
  end

  return setmetatable({ context = ctx }, point)
end

function point:coordinates()
  hogweed.nettle_ecc_point_get(self.context, mpz_t_1, mpz_t_2)
  return {
    x = mpz.tostring(mpz_t_1, 66),
    y = mpz.tostring(mpz_t_2, 66),
  }
end

function point:xy()
  local xy, err = self:coordinates()
  if not xy then
    return nil, err
  end

  return xy.x .. xy.y
end

function point:x()
  local xy, err = self:coordinates()
  if not xy then
    return nil, err
  end

  return xy.x
end

function point:y()
  local xy, err = self:coordinates()
  if not xy then
    return nil, err
  end

  return xy.y
end

local scalar = {}

scalar.__index = scalar

function scalar.new(c, z)
  local ctx = ffi_gc(ffi_new(context.scalar), hogweed.nettle_ecc_scalar_clear)

  c = c or curves["P-256"]

  if type(c) == "cdata" then
    hogweed.nettle_ecc_scalar_init(ctx, c)
  elseif curves[c] then
    hogweed.nettle_ecc_scalar_init(ctx, curves[c])
  else
    return nil, "invalid curve for ECC scalar"
  end

  if z then
    mpz.set(mpz_t_1, z)

    if hogweed.nettle_ecc_scalar_set(ctx, mpz_t_1) ~= 1 then
      return nil, "unable to set ECC scalar"
    end
  end

  return setmetatable({ context = ctx }, scalar)
end


function scalar:d(len)
  hogweed.nettle_ecc_scalar_get(self.context, mpz_t_1)
  return mpz.tostring(mpz_t_1, len)
end

local ecc = { point = point, scalar = scalar, curve = curve }

ecc.__index = ecc

return ecc
