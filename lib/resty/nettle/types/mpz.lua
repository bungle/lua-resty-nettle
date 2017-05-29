local ffi      = require "ffi"
local ffi_cdef = ffi.cdef

ffi_cdef[[
typedef unsigned long mp_limb_t;
typedef struct {
  int _mp_alloc;
  int _mp_size;
  mp_limb_t *_mp_d;
} __mpz_struct;
typedef const __mpz_struct *mpz_srcptr;
typedef __mpz_struct mpz_t[1];
typedef __mpz_struct *mpz_ptr;
]]
