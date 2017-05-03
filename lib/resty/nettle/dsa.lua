-- TODO: THIS IS NOT DONE, IT DOESN'T WORK YET.
require "resty.nettle.types.dsa"
require "resty.nettle.library"

local ffi          = require "ffi"
local ffi_new      = ffi.new
local ffi_cdef     = ffi.cdef
local ffi_typeof   = ffi.typeof

ffi_cdef[[
void nettle_dsa_params_init(struct dsa_params *params);
void nettle_dsa_params_clear(struct dsa_params *params);
void nettle_dsa_signature_init(struct dsa_signature *signature);
void nettle_dsa_signature_clear(struct dsa_signature *signature);
int  nettle_dsa_sign(const struct dsa_params *params, const mpz_t x, void *random_ctx, nettle_random_func *random, size_t digest_size, const uint8_t *digest, struct dsa_signature *signature);
int  nettle_dsa_verify(const struct dsa_params *params, const mpz_t y, size_t digest_size, const uint8_t *digest, const struct dsa_signature *signature);
int  nettle_dsa_generate_params(struct dsa_params *params, void *random_ctx, nettle_random_func *random, void *progress_ctx, nettle_progress_func *progress, unsigned p_bits, unsigned q_bits);
void nettle_dsa_generate_keypair(const struct dsa_params *params, mpz_t pub, mpz_t key, void *random_ctx, nettle_random_func *random);
int  nettle_dsa_keypair_to_sexp(struct nettle_buffer *buffer, const char *algorithm_name, const struct dsa_params *params, const mpz_t pub, const mpz_t priv);
]]
local size = ffi_new "size_t[1]"
local buf = ffi_typeof "uint8_t[?]"

local dsa = { }
dsa.__index = dsa

function dsa.new()
end

function dsa:encrypt()
end

function dsa:decrypt()
end

return dsa
