local ffi = require "ffi"
local ffi_cdef = ffi.cdef

ffi_cdef [[
void
nettle_curve25519_mul_g (uint8_t *q, const uint8_t *n);

void
nettle_curve25519_mul (uint8_t *q, const uint8_t *n, const uint8_t *p);
]]
