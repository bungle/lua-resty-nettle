local ffi = require "ffi"
local ffi_cdef = ffi.cdef
local ffi_typeof = ffi.typeof

ffi_cdef [[
typedef unsigned long int	mp_limb_t;
typedef struct {
  int _mp_alloc;
  int _mp_size;
  mp_limb_t *_mp_d;
} __mpz_struct;
typedef __mpz_struct *mpz_ptr;
typedef const __mpz_struct *mpz_srcptr;
typedef __mpz_struct mpz_t[1];

void __gmpz_clear (mpz_ptr);
void __gmpz_init (mpz_ptr);
void __gmpz_init_set_ui (mpz_ptr, unsigned long int);
void __gmpz_set_ui (mpz_ptr, unsigned long int);
void __gmpz_fdiv_r (mpz_ptr, mpz_srcptr, mpz_srcptr);
void __gmpz_sub_ui (mpz_ptr, mpz_srcptr, unsigned long int);
int  __gmpz_invert (mpz_ptr, mpz_srcptr, mpz_srcptr);

void nettle_mpz_set_str_256_u(mpz_t x, size_t length, const uint8_t *s);
void nettle_mpz_init_set_str_256_u(mpz_t x, size_t length, const uint8_t *s);
void nettle_mpz_get_str_256(size_t length, uint8_t *s, const mpz_t x);
size_t nettle_mpz_sizeinbase_256_u(const mpz_t x);
]]

return ffi_typeof "mpz_t"
