require "resty.nettle.types.mpz"

local ffi      = require "ffi"
local ffi_cdef = ffi.cdef

ffi_cdef[[
struct ecc_curve;
extern const struct ecc_curve nettle_secp_192r1;
extern const struct ecc_curve nettle_secp_224r1;
extern const struct ecc_curve nettle_secp_256r1;
extern const struct ecc_curve nettle_secp_384r1;
extern const struct ecc_curve nettle_secp_521r1;
typedef struct ecc_point {
  const struct ecc_curve *ecc;
  mp_limb_t *p;
} NETTLE_ECC_POINT;
typedef struct ecc_scalar {
  const struct ecc_curve *ecc;
  mp_limb_t *p;
} NETTLE_ECC_SCALAR;
]]
