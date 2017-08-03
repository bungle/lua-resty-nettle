require "resty.nettle.types.des"

local lib        = require "resty.nettle.hogweed"
local ffi        = require "ffi"
local ffi_new    = ffi.new
local ffi_str    = ffi.string
local ffi_cdef   = ffi.cdef
local ffi_typeof = ffi.typeof

local t = ffi_typeof "uint8_t[32]"
local q = ffi_new(t)

ffi_cdef[[
void nettle_curve25519_mul_g(uint8_t *q, const uint8_t *n);
void nettle_curve25519_mul(uint8_t *q, const uint8_t *n, const uint8_t *p);
]]

local curve = {}

function curve.mul(n, p)
    if p then
        lib.nettle_curve25519_mul(q, n, p)
    else
        lib.nettle_curve25519_mul_g(q, n)
    end
    return ffi_str(q, 32);
end

return curve
