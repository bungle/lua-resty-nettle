require "resty.nettle.types.mpz"

local context = require "resty.nettle.types.mpz"
local types = require "resty.nettle.types.common"
local hogweed = require "resty.nettle.hogweed"
local gmp = require "resty.nettle.gmp"

local ffi = require "ffi"
local ffi_gc = ffi.gc
local ffi_str = ffi.string
local ffi_new = ffi.new
local type = type

local mpz = {}
mpz.__index = mpz

function mpz.new(value)
  local mpz_t = ffi_gc(ffi_new(context), gmp.__gmpz_clear)
  if value then
    if type(value) == "string" then
      hogweed.nettle_mpz_init_set_str_256_u(mpz_t, #value, value)
    elseif type(value) == "number" then
      gmp.__gmpz_init_set_ui(mpz_t, value)
    end
  else
    gmp.__gmpz_init(mpz_t)
  end
  return mpz_t
end

function mpz.size(mpz_t)
  return hogweed.nettle_mpz_sizeinbase_256_u(mpz_t)
end

function mpz.invert(rop, op1, op2)
  return gmp.__gmpz_invert(rop, op1, op2)
end

function mpz.sub(rop, op1, op2)
  gmp.__gmpz_sub_ui(rop, op1, op2)
end

function mpz.div(rop, op1, op2)
  gmp.__gmpz_fdiv_r(rop, op1, op2)
end


function mpz.set(mpz_t, value)
  local t = type(value)
  if t == "string" then
    hogweed.nettle_mpz_set_str_256_u(mpz_t, #value, value)
  elseif t == "number" then
    gmp.__gmpz_set_ui(mpz_t, value)
  else
    return nil, "unable to set mpz_t value from an unsupported data type"
  end
  return true
end

function mpz.tostring(mpz_t, len)
  len = len or mpz.size(mpz_t)
  local buf = ffi_new(types.uint8_t, len)
  hogweed.nettle_mpz_get_str_256(len, buf, mpz_t)
  return ffi_str(buf, len)
end

return mpz
