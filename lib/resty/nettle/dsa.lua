-- TODO: THIS IS NOT DONE, IT DOESN'T WORK YET.

require "resty.nettle"

local ffi          = require "ffi"
local ffi_new      = ffi.new
local ffi_load     = ffi.load
local ffi_cdef     = ffi.cdef
local ffi_typeof   = ffi.typeof
local ffi_str      = ffi.string
local assert       = assert
local rawget       = rawget
local setmetatable = setmetatable
local gmp          = require "resty.nettle.gmp"
local buffer       = require "resty.nettle.buffer"
local yarrow       = require "resty.nettle.yarrow"
local knuth        = require "resty.nettle.knuth-lfib"
local hogweed      = ffi_load "hogweed"

ffi_cdef[[
typedef struct dsa_params {
  mpz_t p;
  mpz_t q;
  mpz_t g;
} DSA_PARAMS;
typedef struct dsa_signature {
  mpz_t r;
  mpz_t s;
} DSA_SIGNATURE;
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
local pub = ffi_typeof "RSA_PUBLIC_KEY[1]"
local pri = ffi_typeof "RSA_PRIVATE_KEY[1]"

local keypair = {}
function keypair:__index(n)
    if n == "sexp" then
        local b = buffer.new()
        hogweed.nettle_dsa_keypair_to_sexp(b, nil, self.params.context, self.public.context, self.private.context)
        return ffi_str(b.contents, b.size)
    else
        return rawget(keypair, n)
    end
end
function keypair.new(n, e, r, p, seed)
    n = n or 4096
    e = e or 65537
    local rf, rc
    if r == "knuth-lfib" or r == "knuth" then
        rc = knuth.context(seed)
        rf = knuth.func
    else
        rc = yarrow.context(seed)
        rf = yarrow.func
    end
    local pux = gmp.context()
    local prx = gmp.context()

    assert(hogweed.nettle_rsa_generate_keypair(pux, prx, rc, rf) == 1)
    return setmetatable({
        public  = pux,
        private = prx
    }, keypair)
end

local rsa = { keypair = keypair, key = { public = public, private = private } }
rsa.__index = rsa

function rsa.new(pub, pri)
    if not pub and not pri then
        local kp = keypair.new()
        pub = kp.public
        pri = kp.private
    elseif not pub then
        pub = public.new()
    elseif not pri then
        pri = private.new()
    end
    return setmetatable({ public = pub, private = pri }, rsa)
end

function rsa:encrypt(plain, rc, rf, seed)
    local encrypted = gmp.context()
    local rf, rc
    if r == "knuth-lfib" or r == "knuth" then
        rc = knuth.context(seed)
        rf = knuth.func
    else
        rc = yarrow.context(seed)
        rf = yarrow.func
    end
    local ok = hogweed.nettle_rsa_encrypt(self.public.context, rc, rf, #plain, plain, encrypted)
    if ok == 1 then
        return gmp.string(encrypted)
    end
    return nil
end

function rsa:decrypt(encrypted)
    local ct = gmp.context(encrypted)
    local sz = self.private.context[0].size
    local s = ffi_new(size)
    local b = ffi_new(buf, sz)
    s[0] = sz
    local ok = hogweed.nettle_rsa_decrypt(self.private.context, s, b, ct)
    if ok == 1 then
        return ffi_str(b, s[0])
    end
    return nil
end

return rsa
