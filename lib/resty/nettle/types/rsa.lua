require "resty.nettle.types.mpz"

local ffi      = require "ffi"
local ffi_cdef = ffi.cdef

ffi_cdef[[
typedef struct rsa_public_key {
  size_t size;
  mpz_t n;
  mpz_t e;
} NETTLE_RSA_PUBLIC_KEY;
typedef struct rsa_private_key {
  size_t size;
  mpz_t d;
  mpz_t p;
  mpz_t q;
  mpz_t a;
  mpz_t b;
  mpz_t c;
} NETTLE_RSA_PRIVATE_KEY;
]]
