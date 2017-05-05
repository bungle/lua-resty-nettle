require "resty.nettle.types.dsa"
require "resty.nettle.types.ecc"

local hogweed      = require "resty.nettle.hogweed"
local mpz          = require "resty.nettle.mpz"
local ffi          = require "ffi"
local ffi_gc       = ffi.gc
local ffi_new      = ffi.new
local ffi_cdef     = ffi.cdef
local ffi_typeof   = ffi.typeof
local setmetatable = setmetatable

ffi_cdef[[
void nettle_ecc_point_init(struct ecc_point *p, const struct ecc_curve *ecc);
void nettle_ecc_point_clear(struct ecc_point *p);
int  nettle_ecc_point_set(struct ecc_point *p, const mpz_t x, const mpz_t y);
void nettle_ecc_point_get(const struct ecc_point *p, mpz_t x, mpz_t y);
void nettle_ecc_scalar_init(struct ecc_scalar *s, const struct ecc_curve *ecc);
void nettle_ecc_scalar_clear(struct ecc_scalar *s);
int  nettle_ecc_scalar_set(struct ecc_scalar *s, const mpz_t z);
void nettle_ecc_scalar_get(const struct ecc_scalar *s, mpz_t z);
void nettle_ecc_scalar_random(struct ecc_scalar *s, void *random_ctx, nettle_random_func *random);
void nettle_ecc_point_mul(struct ecc_point *r, const struct ecc_scalar *n, const struct ecc_point *p);
void nettle_ecc_point_mul_g(struct ecc_point *r, const struct ecc_scalar *n);
]]

local pub  = ffi_typeof "ECC_POINT[1]"

local curves = {
    ["P-192"] = hogweed.nettle_secp_192r1,
    ["P-224"] = hogweed.nettle_secp_224r1,
    ["P-256"] = hogweed.nettle_secp_256r1,
    ["P-384"] = hogweed.nettle_secp_384r1,
    ["P-521"] = hogweed.nettle_secp_521r1
}

local curve = {}

curve.__index = curve

local point = {}

point.__index = point

function point.new(curve, x, y, base)
    local context = ffi_gc(ffi_new(pub), hogweed.nettle_ecc_point_clear)

    if curves[curve] then
        hogweed.nettle_ecc_point_init(context, curves[curve])
    end

    if x and y then
        local mx, my, err
        mx, err = mpz.new(x, base)
        if not mx then
            return nil, err
        end
        my, err = mpz.new(y, base)
        if not my then
            return nil, err
        end
        if hogweed.nettle_ecc_point_set(context, mx, my) ~= 1 then
            return nil, "Unable to set ECC point."
        end
    end

    return setmetatable({ context = context }, point)
end

local ecc = { point = point, curve = curve }

ecc.__index = ecc

return ecc
