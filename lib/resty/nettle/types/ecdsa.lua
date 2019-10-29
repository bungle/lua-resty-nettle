require "resty.nettle.types.ecc"

local ffi = require "ffi"
local ffi_cdef = ffi.cdef

ffi_cdef [[
void
nettle_ecdsa_sign(const struct ecc_scalar *key,
	    void *random_ctx, nettle_random_func *random,
	    size_t digest_length,
	    const uint8_t *digest,
	    struct dsa_signature *signature);

int
nettle_ecdsa_verify(const struct ecc_point *pub,
	      size_t length, const uint8_t *digest,
	      const struct dsa_signature *signature);

void
nettle_ecdsa_generate_keypair(struct ecc_point *pub,
			struct ecc_scalar *key,
			void *random_ctx, nettle_random_func *random);
]]
