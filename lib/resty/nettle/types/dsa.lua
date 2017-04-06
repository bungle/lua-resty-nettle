require "resty.nettle.types.gmp"

local ffi        = require "ffi"
local ffi_cdef   = ffi.cdef

ffi_cdef[[
typedef struct dsa_params {
  mpz_t p;
  mpz_t q;
  mpz_t g;
} DSA_PARAMS;
typedef struct dsa_signature {
  mpz_t r;
  mpz_t s;
} DSA_SIGNATURE;
]]
