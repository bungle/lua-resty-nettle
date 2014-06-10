require "resty.nettle.types.md5"
require "resty.nettle.types.ripemd160"
require "resty.nettle.types.sha1"
require "resty.nettle.types.sha2"

local ffi        = require "ffi"
local ffi_new    = ffi.new
local ffi_typeof = ffi.typeof
local ffi_cdef   = ffi.cdef
local ffi_load   = ffi.load
local ffi_str    = ffi.string

ffi_cdef[[
typedef struct hmac_md5_ctx {
  struct md5_ctx outer;
  struct md5_ctx inner;
  struct md5_ctx state;
} HMAC_MD5_CTX;
void nettle_hmac_md5_set_key(struct hmac_md5_ctx *ctx, size_t key_length, const uint8_t *key);
void nettle_hmac_md5_update(struct hmac_md5_ctx *ctx, size_t length, const uint8_t *data);
void nettle_hmac_md5_digest(struct hmac_md5_ctx *ctx, size_t length, uint8_t *digest);
typedef struct hmac_ripemd160_ctx {
  struct ripemd160_ctx outer;
  struct ripemd160_ctx inner;
  struct ripemd160_ctx state;
} HMAC_RIPEMD160_CTX;
void nettle_hmac_ripemd160_set_key(struct hmac_ripemd160_ctx *ctx, size_t key_length, const uint8_t *key);
void nettle_hmac_ripemd160_update(struct hmac_ripemd160_ctx *ctx, size_t length, const uint8_t *data);
void nettle_hmac_ripemd160_digest(struct hmac_ripemd160_ctx *ctx, size_t length, uint8_t *digest);
typedef struct hmac_sha1_ctx {
  struct sha1_ctx outer;
  struct sha1_ctx inner;
  struct sha1_ctx state;
} HMAC_SHA1_CTX;
void nettle_hmac_sha1_set_key(struct hmac_sha1_ctx *ctx, size_t key_length, const uint8_t *key);
void nettle_hmac_sha1_update(struct hmac_sha1_ctx *ctx, size_t length, const uint8_t *data);
void nettle_hmac_sha1_digest(struct hmac_sha1_ctx *ctx, size_t length, uint8_t *digest);
typedef struct hmac_sha256_ctx {
  struct sha256_ctx outer;
  struct sha256_ctx inner;
  struct sha256_ctx state;
} HMAC_SHA256_CTX;
void nettle_hmac_sha224_set_key(struct hmac_sha256_ctx *ctx, size_t key_length, const uint8_t *key);
void nettle_hmac_sha224_digest(struct hmac_sha256_ctx *ctx, size_t length, uint8_t *digest);
void nettle_hmac_sha256_set_key(struct hmac_sha256_ctx *ctx, size_t key_length, const uint8_t *key);
void nettle_hmac_sha256_update(struct hmac_sha256_ctx *ctx, size_t length, const uint8_t *data);
void nettle_hmac_sha256_digest(struct hmac_sha256_ctx *ctx, size_t length, uint8_t *digest);
typedef struct hmac_sha512_ctx {
  struct sha512_ctx outer;
  struct sha512_ctx inner;
  struct sha512_ctx state;
} HMAC_SHA512_CTX;
void nettle_hmac_sha384_set_key(struct hmac_sha512_ctx *ctx, size_t key_length, const uint8_t *key);
void nettle_hmac_sha384_digest(struct hmac_sha512_ctx *ctx, size_t length, uint8_t *digest);
void nettle_hmac_sha512_set_key(struct hmac_sha512_ctx *ctx, size_t key_length, const uint8_t *key);
void nettle_hmac_sha512_update(struct hmac_sha512_ctx *ctx, size_t length, const uint8_t *data);
void nettle_hmac_sha512_digest(struct hmac_sha512_ctx *ctx, size_t length, uint8_t *digest);
]]

local nettle = ffi_load("libnettle")

local uint8t = ffi_typeof("uint8_t[?]")
local ctxmd5 = ffi_typeof("HMAC_MD5_CTX[1]")
local ctx160 = ffi_typeof("HMAC_RIPEMD160_CTX[1]")
local ctxsha = ffi_typeof("HMAC_SHA1_CTX[1]")
local ctx256 = ffi_typeof("HMAC_SHA256_CTX[1]")
local ctx512 = ffi_typeof("HMAC_SHA512_CTX[1]")
local buf128 = ffi_new(uint8t, 16)
local buf160 = ffi_new(uint8t, 20)
local buf224 = ffi_new(uint8t, 28)
local buf256 = ffi_new(uint8t, 32)
local buf384 = ffi_new(uint8t, 48)
local buf512 = ffi_new(uint8t, 64)

local function hmac_sha256_update(self, data)
    return nettle.nettle_hmac_sha256_update(self.context, #data, data)
end

local function hmac_sha512_update(self, data)
    return nettle.nettle_hmac_sha512_update(self.context, #data, data)
end

local md5 = {}
md5.__index = md5

function md5.new(key)
    local self = setmetatable({ context = ffi_new(ctxmd5) }, md5)
    nettle.nettle_hmac_md5_set_key(self.context, #key, key)
    return self
end

function md5:update(data)
    return nettle.nettle_hmac_md5_update(self.context, #data, data)
end

function md5:digest()
    nettle.nettle_hmac_md5_digest(self.context, 16, buf128)
    return ffi_str(buf128, 16)
end

local ripemd160 = {}
ripemd160.__index = ripemd160

function ripemd160.new(key)
    local self = setmetatable({ context = ffi_new(ctx160) }, ripemd160)
    nettle.nettle_hmac_ripemd160_set_key(self.context, #key, key)
    return self
end

function ripemd160:update(data)
    return nettle.nettle_hmac_ripemd160_update(self.context, #data, data)
end

function ripemd160:digest()
    nettle.nettle_hmac_ripemd160_digest(self.context, 20, buf160)
    return ffi_str(buf160, 20)
end

local sha1 = {}
sha1.__index = sha1

function sha1.new(key)
    local self = setmetatable({ context = ffi_new(ctxsha) }, sha1)
    nettle.nettle_hmac_sha1_set_key(self.context, #key, key)
    return self
end

function sha1:update(data)
    return nettle.nettle_hmac_sha1_update(self.context, #data, data)
end

function sha1:digest()
    nettle.nettle_hmac_sha1_digest(self.context, 20, buf160)
    return ffi_str(buf160, 20)
end

local sha224 = { update = hmac_sha256_update }
sha224.__index = sha224

function sha224.new(key)
    local self = setmetatable({ context = ffi_new(ctx256) }, sha224)
    nettle.nettle_hmac_sha224_set_key(self.context, #key, key)
    return self
end

function sha224:digest()
    nettle.nettle_hmac_sha224_digest(self.context, 28, buf224)
    return ffi_str(buf224, 28)
end

local sha256 = { update = hmac_sha256_update }
sha256.__index = sha256

function sha256.new(key)
    local self = setmetatable({ context = ffi_new(ctx256) }, sha256)
    nettle.nettle_hmac_sha256_set_key(self.context, #key, key)
    return self
end

function sha256:digest()
    nettle.nettle_hmac_sha256_digest(self.context, 32, buf256)
    return ffi_str(buf256, 32)
end

local sha384 = { update = hmac_sha512_update }
sha384.__index = sha384

function sha384.new(key)
    local self = setmetatable({ context = ffi_new(ctx512) }, sha384)
    nettle.nettle_hmac_sha384_set_key(self.context, #key, key)
    return self
end

function sha384:digest()
    nettle.nettle_hmac_sha384_digest(self.context, 48, buf384)
    return ffi_str(buf384, 48)
end

local sha512 = { update = hmac_sha512_update }
sha512.__index = sha512

function sha512.new(key)
    local self = setmetatable({ context = ffi_new(ctx512) }, sha512)
    nettle.nettle_hmac_sha512_set_key(self.context, #key, key)
    return self
end

function sha512:digest()
    nettle.nettle_hmac_sha512_digest(self.context, 64, buf512)
    return ffi_str(buf512, 64)
end

return {
    md5       = md5,
    ripemd160 = ripemd160,
    sha1      = sha1,
    sha224    = sha224,
    sha256    = sha256,
    sha384    = sha384,
    sha512    = sha512
}