require "resty.nettle.types.nettle-types"
require "resty.nettle.types.mpz"

local ffi = require "ffi"
local ffi_cdef = ffi.cdef
local ffi_typeof = ffi.typeof

ffi_cdef [[
const struct ecc_curve * nettle_get_secp_192r1(void);
const struct ecc_curve * nettle_get_secp_224r1(void);
const struct ecc_curve * nettle_get_secp_256r1(void);
const struct ecc_curve * nettle_get_secp_384r1(void);
const struct ecc_curve * nettle_get_secp_521r1(void);

void
nettle_ecc_point_init (struct ecc_point *p, const struct ecc_curve *ecc);

void
nettle_ecc_point_clear (struct ecc_point *p);

int
nettle_ecc_point_set (struct ecc_point *p, const mpz_t x, const mpz_t y);

void
nettle_ecc_point_get (const struct ecc_point *p, mpz_t x, mpz_t y);

void
nettle_ecc_scalar_init (struct ecc_scalar *s, const struct ecc_curve *ecc);

void
nettle_ecc_scalar_clear (struct ecc_scalar *s);

int
nettle_ecc_scalar_set (struct ecc_scalar *s, const mpz_t z);

void
nettle_ecc_scalar_get (const struct ecc_scalar *s, mpz_t z);

void
nettle_ecc_scalar_random (struct ecc_scalar *s,
		   void *random_ctx, nettle_random_func *random);

void
nettle_ecc_point_mul (struct ecc_point *r, const struct ecc_scalar *n,
	       const struct ecc_point *p);

void
nettle_ecc_point_mul_g (struct ecc_point *r, const struct ecc_scalar *n);
]]

return {
  point = ffi_typeof [[
struct ecc_point {
  const struct ecc_curve *ecc;
  mp_limb_t *p;
}]],
  scalar = ffi_typeof [[
struct ecc_scalar {
  const struct ecc_curve *ecc;
  mp_limb_t *p;
}]],
  curve = ffi_typeof "struct ecc_curve",
}

