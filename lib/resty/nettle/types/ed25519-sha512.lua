local ffi = require "ffi"
local ffi_cdef = ffi.cdef

ffi_cdef [[
void
nettle_ed25519_sha512_public_key (uint8_t *pub, const uint8_t *priv);

void
nettle_ed25519_sha512_sign (const uint8_t *pub,
		     const uint8_t *priv,
		     size_t length, const uint8_t *msg,
		     uint8_t *signature);

int
nettle_ed25519_sha512_verify (const uint8_t *pub,
		       size_t length, const uint8_t *msg,
		       const uint8_t *signature);
]]
