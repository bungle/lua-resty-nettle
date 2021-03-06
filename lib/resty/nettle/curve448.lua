require "resty.nettle.types.curve448"

local types = require "resty.nettle.types.common"
local lib = require "resty.nettle.hogweed"
local ffi = require "ffi"
local ffi_str = ffi.string

local curve = {}

function curve.mul(n, p)
  if p then
    lib.nettle_curve448_mul(types.uint8_t_32, n, p)
  else
    lib.nettle_curve448_mul_g(types.uint8_t_32, n)
  end
  return ffi_str(types.uint8_t_56, 56);
end

return curve
