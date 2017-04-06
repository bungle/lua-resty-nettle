-- TODO: THIS IS NOT DONE, IT DOESN'T WORK YET.
require "resty.nettle.types.dsa"
require "resty.nettle.types.ecc"

local hogweed  = require "resty.nettle.library"
local ffi      = require "ffi"
local ffi_cdef = ffi.cdef

ffi_cdef[[
void  ecc_point_init(struct ecc_point *p, const struct ecc_curve *ecc);
void  ecc_point_clear(struct ecc_point *p);
int   ecc_point_set(struct ecc_point *p, const mpz_t x, const mpz_t y);
void  ecc_point_get(const struct ecc_point *p, mpz_t x, mpz_t y);
void  ecc_scalar_init(struct ecc_scalar *s, const struct ecc_curve *ecc);
void  ecc_scalar_clear(struct ecc_scalar *s);
int   ecc_scalar_set(struct ecc_scalar *s, const mpz_t z);
void  ecc_scalar_get(const struct ecc_scalar *s, mpz_t z);
void  ecc_scalar_random(struct ecc_scalar *s, void *random_ctx, nettle_random_func *random);
void  ecc_point_mul(struct ecc_point *r, const struct ecc_scalar *n, const struct ecc_point *p);
void  ecc_point_mul_g(struct ecc_point *r, const struct ecc_scalar *n);
]]
