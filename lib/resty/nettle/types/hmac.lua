require "resty.nettle.types.md5"
require "resty.nettle.types.ripemd160"
require "resty.nettle.types.sha1"
require "resty.nettle.types.sha2"

local ffi = require "ffi"
local ffi_cdef = ffi.cdef
local ffi_typeof = ffi.typeof

ffi_cdef [[
void
nettle_hmac_set_key(void *outer, void *inner, void *state,
                    const struct nettle_hash *hash,
                    size_t length, const uint8_t *key);

void
nettle_hmac_update(void *state,
                   const struct nettle_hash *hash,
                   size_t length, const uint8_t *data);

void
nettle_hmac_digest(const void *outer, const void *inner, void *state,
                   const struct nettle_hash *hash,
                   size_t length, uint8_t *digest);

void
nettle_hmac_md5_set_key(struct hmac_md5_ctx *ctx,
                        size_t key_length, const uint8_t *key);

void
nettle_hmac_md5_update(struct hmac_md5_ctx *ctx,
                       size_t length, const uint8_t *data);

void
nettle_hmac_md5_digest(struct hmac_md5_ctx *ctx,
                       size_t length, uint8_t *digest);

void
nettle_hmac_ripemd160_set_key(struct hmac_ripemd160_ctx *ctx,
                              size_t key_length, const uint8_t *key);

void
nettle_hmac_ripemd160_update(struct hmac_ripemd160_ctx *ctx,
                             size_t length, const uint8_t *data);

void
nettle_hmac_ripemd160_digest(struct hmac_ripemd160_ctx *ctx,
                             size_t length, uint8_t *digest);

void
nettle_hmac_sha1_set_key(struct hmac_sha1_ctx *ctx,
                         size_t key_length, const uint8_t *key);

void
nettle_hmac_sha1_update(struct hmac_sha1_ctx *ctx,
                        size_t length, const uint8_t *data);

void
nettle_hmac_sha1_digest(struct hmac_sha1_ctx *ctx,
                        size_t length, uint8_t *digest);

void
nettle_hmac_sha256_set_key(struct hmac_sha256_ctx *ctx,
                           size_t key_length, const uint8_t *key);

void
nettle_hmac_sha256_update(struct hmac_sha256_ctx *ctx,
                          size_t length, const uint8_t *data);

void
nettle_hmac_sha256_digest(struct hmac_sha256_ctx *ctx,
                          size_t length, uint8_t *digest);

void
nettle_hmac_sha224_set_key(struct hmac_sha256_ctx *ctx,
                           size_t key_length, const uint8_t *key);

void
nettle_hmac_sha224_digest(struct hmac_sha256_ctx *ctx,
                          size_t length, uint8_t *digest);

void
nettle_hmac_sha512_set_key(struct hmac_sha512_ctx *ctx,
                           size_t key_length, const uint8_t *key);

void
nettle_hmac_sha512_update(struct hmac_sha512_ctx *ctx,
                          size_t length, const uint8_t *data);

void
nettle_hmac_sha512_digest(struct hmac_sha512_ctx *ctx,
                          size_t length, uint8_t *digest);

void
nettle_hmac_sha384_set_key(struct hmac_sha512_ctx *ctx,
                           size_t key_length, const uint8_t *key);

void
nettle_hmac_sha384_digest(struct hmac_sha512_ctx *ctx,
                          size_t length, uint8_t *digest);
]]


local sha256 = ffi_typeof [[
struct hmac_sha256_ctx {
  struct sha256_ctx outer;
  struct sha256_ctx inner;
  struct sha256_ctx state;
}]]

local sha512 = ffi_typeof [[
struct hmac_sha512_ctx {
  struct sha512_ctx outer;
  struct sha512_ctx inner;
  struct sha512_ctx state;
}]]

return {
  md5 = ffi_typeof [[
struct hmac_md5_ctx {
  struct md5_ctx outer;
  struct md5_ctx inner;
  struct md5_ctx state;
}]],
  ripemd160 = ffi_typeof [[
struct hmac_ripemd160_ctx {
  struct ripemd160_ctx outer;
  struct ripemd160_ctx inner;
  struct ripemd160_ctx state;
}]],
  sha1 = ffi_typeof [[
struct hmac_sha1_ctx {
  struct sha1_ctx outer;
  struct sha1_ctx inner;
  struct sha1_ctx state;
}]],
  sha224 = sha256,
  sha256 = sha256,
  sha384 = sha512,
  sha512 = sha512,
}
