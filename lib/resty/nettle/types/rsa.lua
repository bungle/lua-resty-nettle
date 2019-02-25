require "resty.nettle.types.mpz"

local ffi = require "ffi"
local ffi_cdef = ffi.cdef
local ffi_typeof = ffi.typeof

ffi_cdef [[
void
nettle_rsa_public_key_init(struct rsa_public_key *key);

void
nettle_rsa_public_key_clear(struct rsa_public_key *key);

int
nettle_rsa_public_key_prepare(struct rsa_public_key *key);

void
nettle_rsa_private_key_init(struct rsa_private_key *key);

void
nettle_rsa_private_key_clear(struct rsa_private_key *key);

int
nettle_rsa_private_key_prepare(struct rsa_private_key *key);


int
nettle_rsa_pkcs1_sign(const struct rsa_private_key *key,
	       size_t length, const uint8_t *digest_info,
	       mpz_t s);

int
nettle_rsa_pkcs1_sign_tr(const struct rsa_public_key *pub,
            const struct rsa_private_key *key,
	          void *random_ctx, nettle_random_func *random,
	          size_t length, const uint8_t *digest_info,
            mpz_t s);

int
nettle_rsa_pkcs1_verify(const struct rsa_public_key *key,
		 size_t length, const uint8_t *digest_info,
		 const mpz_t signature);

int
nettle_rsa_md5_sign(const struct rsa_private_key *key,
             struct md5_ctx *hash,
             mpz_t signature);

int
nettle_rsa_md5_sign_tr(const struct rsa_public_key *pub,
		const struct rsa_private_key *key,
		void *random_ctx, nettle_random_func *random,
		struct md5_ctx *hash, mpz_t s);

int
nettle_rsa_md5_verify(const struct rsa_public_key *key,
               struct md5_ctx *hash,
	       const mpz_t signature);

int
nettle_rsa_sha1_sign(const struct rsa_private_key *key,
              struct sha1_ctx *hash,
              mpz_t signature);

int
nettle_rsa_sha1_sign_tr(const struct rsa_public_key *pub,
		 const struct rsa_private_key *key,
		 void *random_ctx, nettle_random_func *random,
		 struct sha1_ctx *hash,
		 mpz_t s);

int
nettle_rsa_sha1_verify(const struct rsa_public_key *key,
                struct sha1_ctx *hash,
		const mpz_t signature);

int
nettle_rsa_sha256_sign(const struct rsa_private_key *key,
		struct sha256_ctx *hash,
		mpz_t signature);

int
nettle_rsa_sha256_sign_tr(const struct rsa_public_key *pub,
		   const struct rsa_private_key *key,
		   void *random_ctx, nettle_random_func *random,
		   struct sha256_ctx *hash,
		   mpz_t s);

int
nettle_rsa_sha256_verify(const struct rsa_public_key *key,
		  struct sha256_ctx *hash,
		  const mpz_t signature);

int
nettle_rsa_sha512_sign(const struct rsa_private_key *key,
		struct sha512_ctx *hash,
		mpz_t signature);

int
nettle_rsa_sha512_sign_tr(const struct rsa_public_key *pub,
		   const struct rsa_private_key *key,
		   void *random_ctx, nettle_random_func *random,
		   struct sha512_ctx *hash,
		   mpz_t s);

int
nettle_rsa_sha512_verify(const struct rsa_public_key *key,
		  struct sha512_ctx *hash,
		  const mpz_t signature);

int
nettle_rsa_md5_sign_digest(const struct rsa_private_key *key,
		    const uint8_t *digest,
		    mpz_t s);

int
nettle_rsa_md5_sign_digest_tr(const struct rsa_public_key *pub,
		       const struct rsa_private_key *key,
		       void *random_ctx, nettle_random_func *random,
		       const uint8_t *digest, mpz_t s);

int
nettle_rsa_md5_verify_digest(const struct rsa_public_key *key,
		      const uint8_t *digest,
		      const mpz_t signature);

int
nettle_rsa_sha1_sign_digest(const struct rsa_private_key *key,
		     const uint8_t *digest,
		     mpz_t s);

int
nettle_rsa_sha1_sign_digest_tr(const struct rsa_public_key *pub,
			const struct rsa_private_key *key,
			void *random_ctx, nettle_random_func *random,
			const uint8_t *digest,
			mpz_t s);

int
nettle_rsa_sha1_verify_digest(const struct rsa_public_key *key,
		       const uint8_t *digest,
		       const mpz_t signature);

int
nettle_rsa_sha256_sign_digest(const struct rsa_private_key *key,
		       const uint8_t *digest,
		       mpz_t s);

int
nettle_rsa_sha256_sign_digest_tr(const struct rsa_public_key *pub,
			  const struct rsa_private_key *key,
			  void *random_ctx, nettle_random_func *random,
			  const uint8_t *digest,
			  mpz_t s);

int
nettle_rsa_sha256_verify_digest(const struct rsa_public_key *key,
			 const uint8_t *digest,
			 const mpz_t signature);

int
nettle_rsa_sha512_sign_digest(const struct rsa_private_key *key,
		       const uint8_t *digest,
		       mpz_t s);

int
nettle_rsa_sha512_sign_digest_tr(const struct rsa_public_key *pub,
			  const struct rsa_private_key *key,
			  void *random_ctx, nettle_random_func *random,
			  const uint8_t *digest,
			  mpz_t s);

int
nettle_rsa_sha512_verify_digest(const struct rsa_public_key *key,
			 const uint8_t *digest,
			 const mpz_t signature);

int
nettle_rsa_pss_sha256_sign_digest_tr(const struct rsa_public_key *pub,
			      const struct rsa_private_key *key,
			      void *random_ctx, nettle_random_func *random,
			      size_t salt_length, const uint8_t *salt,
			      const uint8_t *digest,
			      mpz_t s);

int
nettle_rsa_pss_sha256_verify_digest(const struct rsa_public_key *key,
			     size_t salt_length,
			     const uint8_t *digest,
			     const mpz_t signature);

int
nettle_rsa_pss_sha384_sign_digest_tr(const struct rsa_public_key *pub,
			      const struct rsa_private_key *key,
			      void *random_ctx, nettle_random_func *random,
			      size_t salt_length, const uint8_t *salt,
			      const uint8_t *digest,
			      mpz_t s);

int
nettle_rsa_pss_sha384_verify_digest(const struct rsa_public_key *key,
			     size_t salt_length,
			     const uint8_t *digest,
			     const mpz_t signature);

int
nettle_rsa_pss_sha512_sign_digest_tr(const struct rsa_public_key *pub,
			      const struct rsa_private_key *key,
			      void *random_ctx, nettle_random_func *random,
			      size_t salt_length, const uint8_t *salt,
			      const uint8_t *digest,
			      mpz_t s);

int
nettle_rsa_pss_sha512_verify_digest(const struct rsa_public_key *key,
			     size_t salt_length,
			     const uint8_t *digest,
			     const mpz_t signature);

int
nettle_rsa_encrypt(const struct rsa_public_key *key,
	    void *random_ctx, nettle_random_func *random,
	    size_t length, const uint8_t *cleartext,
	    mpz_t cipher);

int
nettle_rsa_decrypt(const struct rsa_private_key *key,
	    size_t *length, uint8_t *cleartext,
	    const mpz_t ciphertext);

int
nettle_rsa_decrypt_tr(const struct rsa_public_key *pub,
	       const struct rsa_private_key *key,
	       void *random_ctx, nettle_random_func *random,
	       size_t *length, uint8_t *message,
	       const mpz_t gibberish);

int
nettle_rsa_sec_decrypt(const struct rsa_public_key *pub,
	        const struct rsa_private_key *key,
	        void *random_ctx, nettle_random_func *random,
	        size_t length, uint8_t *message,
	        const mpz_t gibberish);

void
nettle_rsa_compute_root(const struct rsa_private_key *key,
		 mpz_t x, const mpz_t m);

int
nettle_rsa_compute_root_tr(const struct rsa_public_key *pub,
		    const struct rsa_private_key *key,
		    void *random_ctx, nettle_random_func *random,
		    mpz_t x, const mpz_t m);

int
nettle_rsa_generate_keypair(struct rsa_public_key *pub,
		     struct rsa_private_key *key,
		     void *random_ctx, nettle_random_func *random,
		     void *progress_ctx, nettle_progress_func *progress,
		     unsigned n_size,
		     unsigned e_size);

int
nettle_rsa_keypair_to_sexp(struct nettle_buffer *buffer,
		    const char *algorithm_name,
		    const struct rsa_public_key *pub,
		    const struct rsa_private_key *priv);

int
nettle_rsa_keypair_from_sexp_alist(struct rsa_public_key *pub,
			    struct rsa_private_key *priv,
			    unsigned limit,
			    struct sexp_iterator *i);

int
nettle_rsa_keypair_from_sexp(struct rsa_public_key *pub,
		      struct rsa_private_key *priv,
		      unsigned limit,
		      size_t length, const uint8_t *expr);

int
nettle_rsa_public_key_from_der_iterator(struct rsa_public_key *pub,
				 unsigned limit,
				 struct asn1_der_iterator *i);

int
nettle_rsa_private_key_from_der_iterator(struct rsa_public_key *pub,
				  struct rsa_private_key *priv,
				  unsigned limit,
				  struct asn1_der_iterator *i);

int
nettle_rsa_keypair_from_der(struct rsa_public_key *pub,
		     struct rsa_private_key *priv,
		     unsigned limit,
		     size_t length, const uint8_t *data);

int
nettle_rsa_keypair_to_openpgp(struct nettle_buffer *buffer,
		       const struct rsa_public_key *pub,
		       const struct rsa_private_key *priv,
		       const char *userid);
]]

return {
  public = ffi_typeof [[
struct rsa_public_key{
  size_t size;
  mpz_t n;
  mpz_t e;
}]],
  private = ffi_typeof [[
struct rsa_private_key {
  size_t size;
  mpz_t d;
  mpz_t p; mpz_t q;
  mpz_t a;
  mpz_t b;
  mpz_t c;
}]]
}
