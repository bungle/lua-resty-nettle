require "resty.nettle.types.mpz"
require "resty.nettle.types.nettle-types"

local ffi = require "ffi"
local ffi_cdef = ffi.cdef
local ffi_typeof = ffi.typeof

ffi_cdef [[
void
nettle_dsa_params_init (struct dsa_params *params);

void
nettle_dsa_params_clear (struct dsa_params *params);

void
nettle_dsa_signature_init(struct dsa_signature *signature);

void
nettle_dsa_signature_clear(struct dsa_signature *signature);

int
nettle_dsa_sign(const struct dsa_params *params,
	 const mpz_t x,
	 void *random_ctx, nettle_random_func *random,
	 size_t digest_size,
	 const uint8_t *digest,
	 struct dsa_signature *signature);

int
nettle_dsa_verify(const struct dsa_params *params,
	   const mpz_t y,
	   size_t digest_size,
	   const uint8_t *digest,
	   const struct dsa_signature *signature);


int
nettle_dsa_generate_params(struct dsa_params *params,
		    void *random_ctx, nettle_random_func *random,
		    void *progress_ctx, nettle_progress_func *progress,
		    unsigned p_bits, unsigned q_bits);

void
nettle_dsa_generate_keypair(const struct dsa_params *params,
		      mpz_t pub, mpz_t key,
		      void *random_ctx, nettle_random_func *random);

int
nettle_dsa_keypair_to_sexp(struct nettle_buffer *buffer,
		    const char *algorithm_name,
		    const struct dsa_params *params,
		    const mpz_t pub,
		    const mpz_t priv);

int
nettle_dsa_signature_from_sexp(struct dsa_signature *rs,
			struct sexp_iterator *i,
			unsigned q_bits);

int
nettle_dsa_keypair_from_sexp_alist(struct dsa_params *params,
			    mpz_t pub,
			    mpz_t priv,
			    unsigned p_max_bits,
			    unsigned q_bits,
			    struct sexp_iterator *i);

int
nettle_dsa_sha1_keypair_from_sexp(struct dsa_params *params,
			   mpz_t pub,
			   mpz_t priv,
			   unsigned p_max_bits,
			   size_t length, const uint8_t *expr);

int
nettle_dsa_sha256_keypair_from_sexp(struct dsa_params *params,
			     mpz_t pub,
			     mpz_t priv,
			     unsigned p_max_bits,
			     size_t length, const uint8_t *expr);

int
nettle_dsa_params_from_der_iterator(struct dsa_params *params,
			     unsigned max_bits, unsigned q_bits,
			     struct asn1_der_iterator *i);

int
nettle_dsa_public_key_from_der_iterator(const struct dsa_params *params,
				 mpz_t pub,
				 struct asn1_der_iterator *i);

int
nettle_dsa_openssl_private_key_from_der_iterator(struct dsa_params *params,
					  mpz_t pub,
					  mpz_t priv,
					  unsigned p_max_bits,
					  struct asn1_der_iterator *i);

int
nettle_dsa_openssl_private_key_from_der(struct dsa_params *params,
				 mpz_t pub,
				 mpz_t priv,
				 unsigned p_max_bits,
				 size_t length, const uint8_t *data);
]]

return {
  params = ffi_typeof [[
struct dsa_params {
  mpz_t p;
  mpz_t q;
  mpz_t g;
}]],
  signature = ffi_typeof [[
struct dsa_signature {
  mpz_t r;
  mpz_t s;
}]]
}

