require "resty.nettle.types.mpz"

local ffi      = require "ffi"
local ffi_cdef = ffi.cdef

ffi_cdef[[
typedef struct dsa_params {
  mpz_t p;
  mpz_t q;
  mpz_t g;
} NETTLE_DSA_PARAMS;
typedef struct dsa_signature {
  mpz_t r;
  mpz_t s;
} NETTLE_DSA_SIGNATURE;
]]
