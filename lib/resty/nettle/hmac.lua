require "resty.nettle.types.md5"
require "resty.nettle.types.ripemd160"
require "resty.nettle.types.sha1"
require "resty.nettle.types.sha2"

local nettle       = require "resty.nettle"
local ffi          = require "ffi"
local ffi_new      = ffi.new
local ffi_typeof   = ffi.typeof
local ffi_cdef     = ffi.cdef
local ffi_str      = ffi.string
local assert       = assert
local setmetatable = setmetatable

ffi_cdef[[
typedef struct hmac_md5_ctx {
  struct md5_ctx outer;
  struct md5_ctx inner;
  struct md5_ctx state;
} HMAC_MD5_CTX;
void nettle_hmac_md5_set_key(struct hmac_md5_ctx *ctx, size_t key_length, const uint8_t *key);
void nettle_hmac_md5_update (struct hmac_md5_ctx *ctx, size_t length, const uint8_t *data);
void nettle_hmac_md5_digest (struct hmac_md5_ctx *ctx, size_t length, uint8_t *digest);
typedef struct hmac_sha1_ctx {
  struct sha1_ctx outer;
  struct sha1_ctx inner;
  struct sha1_ctx state;
} HMAC_SHA1_CTX;
void nettle_hmac_sha1_set_key(struct hmac_sha1_ctx *ctx, size_t key_length, const uint8_t *key);
void nettle_hmac_sha1_update (struct hmac_sha1_ctx *ctx, size_t length, const uint8_t *data);
void nettle_hmac_sha1_digest (struct hmac_sha1_ctx *ctx, size_t length, uint8_t *digest);
typedef struct hmac_sha256_ctx {
  struct sha256_ctx outer;
  struct sha256_ctx inner;
  struct sha256_ctx state;
} HMAC_SHA256_CTX;
void nettle_hmac_sha224_set_key(struct hmac_sha256_ctx *ctx, size_t key_length, const uint8_t *key);
void nettle_hmac_sha224_digest (struct hmac_sha256_ctx *ctx, size_t length, uint8_t *digest);
void nettle_hmac_sha256_set_key(struct hmac_sha256_ctx *ctx, size_t key_length, const uint8_t *key);
void nettle_hmac_sha256_update (struct hmac_sha256_ctx *ctx, size_t length, const uint8_t *data);
void nettle_hmac_sha256_digest (struct hmac_sha256_ctx *ctx, size_t length, uint8_t *digest);
typedef struct hmac_sha512_ctx {
  struct sha512_ctx outer;
  struct sha512_ctx inner;
  struct sha512_ctx state;
} HMAC_SHA512_CTX;
void nettle_hmac_sha384_set_key(struct hmac_sha512_ctx *ctx, size_t key_length, const uint8_t *key);
void nettle_hmac_sha384_digest (struct hmac_sha512_ctx *ctx, size_t length, uint8_t *digest);
void nettle_hmac_sha512_set_key(struct hmac_sha512_ctx *ctx, size_t key_length, const uint8_t *key);
void nettle_hmac_sha512_update (struct hmac_sha512_ctx *ctx, size_t length, const uint8_t *data);
void nettle_hmac_sha512_digest (struct hmac_sha512_ctx *ctx, size_t length, uint8_t *digest);
typedef struct hmac_ripemd160_ctx {
  struct ripemd160_ctx outer;
  struct ripemd160_ctx inner;
  struct ripemd160_ctx state;
} HMAC_RIPEMD160_CTX;
void nettle_hmac_ripemd160_set_key(struct hmac_ripemd160_ctx *ctx, size_t key_length, const uint8_t *key);
void nettle_hmac_ripemd160_update (struct hmac_ripemd160_ctx *ctx, size_t length, const uint8_t *data);
void nettle_hmac_ripemd160_digest (struct hmac_ripemd160_ctx *ctx, size_t length, uint8_t *digest);
]]

local uint8t = ffi_typeof "uint8_t[?]"
local ctxmd5 = ffi_typeof "HMAC_MD5_CTX[1]"
local ctx160 = ffi_typeof "HMAC_RIPEMD160_CTX[1]"
local ctxsha = ffi_typeof "HMAC_SHA1_CTX[1]"
local ctx256 = ffi_typeof "HMAC_SHA256_CTX[1]"
local ctx512 = ffi_typeof "HMAC_SHA512_CTX[1]"
local buf128 = ffi_new(uint8t, 16)
local buf160 = ffi_new(uint8t, 20)
local buf224 = ffi_new(uint8t, 28)
local buf256 = ffi_new(uint8t, 32)
local buf384 = ffi_new(uint8t, 48)
local buf512 = ffi_new(uint8t, 64)

local hmacs = {
    md5 = {
        length  = 16,
        context = ctxmd5,
        buffer  = buf128,
        setkey  = nettle.nettle_hmac_md5_set_key,
        update  = nettle.nettle_hmac_md5_update,
        digest  = nettle.nettle_hmac_md5_digest
    },
    sha1 = {
        length  = 20,
        context = ctxsha,
        buffer  = buf160,
        setkey  = nettle.nettle_hmac_sha1_set_key,
        update  = nettle.nettle_hmac_sha1_update,
        digest  = nettle.nettle_hmac_sha1_digest
    },
    sha224 = {
        length  = 28,
        context = ctx256,
        buffer  = buf224,
        setkey  = nettle.nettle_hmac_sha224_set_key,
        update  = nettle.nettle_hmac_sha256_update,
        digest  = nettle.nettle_hmac_sha224_digest
    },
    sha256 = {
        length  = 32,
        context = ctx256,
        buffer  = buf256,
        setkey  = nettle.nettle_hmac_sha256_set_key,
        update  = nettle.nettle_hmac_sha256_update,
        digest  = nettle.nettle_hmac_sha256_digest
    },
    sha384 = {
        length  = 48,
        context = ctx512,
        buffer  = buf384,
        setkey  = nettle.nettle_hmac_sha384_set_key,
        update  = nettle.nettle_hmac_sha512_update,
        digest  = nettle.nettle_hmac_sha384_digest
    },
    sha512 = {
        length  = 64,
        context = ctx512,
        buffer  = buf512,
        setkey  = nettle.nettle_hmac_sha512_set_key,
        update  = nettle.nettle_hmac_sha512_update,
        digest  = nettle.nettle_hmac_sha512_digest
    },
    ripemd160 = {
        length  = 20,
        context = ctx160,
        buffer  = buf160,
        setkey  = nettle.nettle_hmac_ripemd160_set_key,
        update  = nettle.nettle_hmac_ripemd160_update,
        digest  = nettle.nettle_hmac_ripemd160_digest
    }
}

local hmac = {}
hmac.__index = hmac

function hmac:update(data, len)
    return self.hmac.update(self.context, len or #data, data)
end

function hmac:digest()
    local hmac = self.hmac
    hmac.digest(self.context, hmac.length, hmac.buffer)
    return ffi_str(hmac.buffer, hmac.length)
end

local function factory(mac)
    return setmetatable({ new = function(key)
        local ctx = ffi_new(mac.context)
        mac.setkey(ctx, #key, key)
        return setmetatable({ context = ctx, hmac = mac }, hmac)
    end }, {
        __call = function(_, key, data, len)
            local ctx = ffi_new(mac.context)
            mac.setkey(ctx, #key, key)
            mac.update(ctx, len or #data, data)
            mac.digest(ctx, mac.length, mac.buffer)
            return ffi_str(mac.buffer, mac.length)
        end
    })
end

return setmetatable({
    md5       = factory(hmacs.md5),
    sha1      = factory(hmacs.sha1),
    sha224    = factory(hmacs.sha224),
    sha256    = factory(hmacs.sha256),
    sha384    = factory(hmacs.sha384),
    sha512    = factory(hmacs.sha512),
    ripemd160 = factory(hmacs.ripemd160),
}, { __call = function(_, algorithm, key, data, len)
    local mac = hmacs[algorithm:lower()]
    assert(mac, "The supported HMAC algorithms are MD5, SHA1, SHA224, SHA256, SHA384, SHA512, and RIPEMD160.")
    local ctx = ffi_new(mac.context)
    mac.setkey(ctx, #key, key)
    mac.update(ctx, len or #data, data)
    mac.digest(ctx, mac.length, mac.buffer)
    return ffi_str(mac.buffer, mac.length)
end })