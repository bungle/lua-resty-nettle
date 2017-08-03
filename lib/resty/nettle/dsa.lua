require "resty.nettle.types.dsa"
require "resty.nettle.library"

local hogweed      = require "resty.nettle.hogweed"
local mpz          = require "resty.nettle.mpz"
local ffi          = require "ffi"
local ffi_gc       = ffi.gc
local ffi_new      = ffi.new
local ffi_cdef     = ffi.cdef
local ffi_typeof   = ffi.typeof
local setmetatable = setmetatable

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
local sig = ffi_typeof "NETTLE_DSA_SIGNATURE[1]"

local signature = {}

signature.__index = signature

function signature.new(r, s, base)
    local context = ffi_gc(ffi_new(sig), hogweed.nettle_dsa_signature_clear)
    hogweed.nettle_dsa_signature_init(context)
    if r then
        local ok, err = mpz.set(context[0].r, r, base)
        if not ok then
            return nil, err
        end
    end

    if s then
        local ok, err = mpz.set(context[0].s, s, base)
        if not ok then
            return nil, err
        end
    end

    return setmetatable({ context = context }, signature)
end

local dsa = { signature = signature }
dsa.__index = dsa

function dsa.new()
end

function dsa:encrypt()
end

function dsa:decrypt()
end

return dsa
