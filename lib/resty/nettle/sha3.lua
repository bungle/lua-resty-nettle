local ffi        = require "ffi"
local ffi_new    = ffi.new
local ffi_typeof = ffi.typeof
local ffi_cdef   = ffi.cdef
local ffi_load   = ffi.load
local ffi_str    = ffi.string

ffi_cdef[[
typedef struct sha3_state {
  uint64_t a[25];
} SHA3_STATE;
typedef struct sha3_224_ctx {
  struct sha3_state state;
  unsigned index;
  uint8_t block[144];
} SHA3_224_CTX;
void nettle_sha3_224_init(struct sha3_224_ctx *ctx);
void nettle_sha3_224_update(struct sha3_224_ctx *ctx, size_t length, const uint8_t *data);
void nettle_sha3_224_digest(struct sha3_224_ctx *ctx, size_t length, uint8_t *digest);
typedef struct sha3_256_ctx {
  struct sha3_state state;
  unsigned index;
  uint8_t block[136];
} SHA3_256_CTX;
void nettle_sha3_256_init(struct sha3_256_ctx *ctx);
void nettle_sha3_256_update(struct sha3_256_ctx *ctx, size_t length, const uint8_t *data);
void nettle_sha3_256_digest(struct sha3_256_ctx *ctx, size_t length, uint8_t *digest);
typedef struct sha3_384_ctx {
  struct sha3_state state;
  unsigned index;
  uint8_t block[104];
} SHA3_384_CTX;
void nettle_sha3_384_init(struct sha3_384_ctx *ctx);
void nettle_sha3_384_update(struct sha3_384_ctx *ctx, size_t length, const uint8_t *data);
void nettle_sha3_384_digest(struct sha3_384_ctx *ctx, size_t length, uint8_t *digest);
typedef struct sha3_512_ctx {
  struct sha3_state state;
  unsigned index;
  uint8_t block[72];
} SHA3_512_CTX;
void nettle_sha3_512_init(struct sha3_512_ctx *ctx);
void nettle_sha3_512_update(struct sha3_512_ctx *ctx, size_t length, const uint8_t *data);
void nettle_sha3_512_digest(struct sha3_512_ctx *ctx, size_t length, uint8_t *digest);
]]

local nettle = ffi_load("libnettle")

local ctx224 = ffi_typeof("SHA3_224_CTX[1]")
local ctx256 = ffi_typeof("SHA3_256_CTX[1]")
local ctx384 = ffi_typeof("SHA3_384_CTX[1]")
local ctx512 = ffi_typeof("SHA3_512_CTX[1]")
local buf224 = ffi_new("uint8_t[?]", 28)
local buf256 = ffi_new("uint8_t[?]", 32)
local buf384 = ffi_new("uint8_t[?]", 48)
local buf512 = ffi_new("uint8_t[?]", 64)

local sha224 = {}
sha224.__index = sha224

function sha224.new()
    local self = setmetatable({ context = ffi_new(ctx224) }, sha224)
    nettle.nettle_sha3_224_init(self.context)
    return self
end

function sha224:update(data)
    return nettle.nettle_sha3_224_update(self.context, #data, data)
end

function sha224:digest()
    nettle.nettle_sha3_224_digest(self.context, 28, buf224)
    return ffi_str(buf224, 28)
end

local sha256 = {}
sha256.__index = sha256

function sha256.new()
    local self = setmetatable({ context = ffi_new(ctx256) }, sha256)
    nettle.nettle_sha3_256_init(self.context)
    return self
end

function sha256:update(data)
    return nettle.nettle_sha3_256_update(self.context, #data, data)
end

function sha256:digest()
    nettle.nettle_sha3_256_digest(self.context, 32, buf256)
    return ffi_str(buf256, 32)
end

local sha384 = {}
sha384.__index = sha384

function sha384.new()
    local self = setmetatable({ context = ffi_new(ctx384) }, sha384)
    nettle.nettle_sha3_384_init(self.context)
    return self
end

function sha384:update(data)
    return nettle.nettle_sha3_384_update(self.context, #data, data)
end

function sha384:digest()
    nettle.nettle_sha3_384_digest(self.context, 48, buf384)
    return ffi_str(buf384, 48)
end

local sha512 = {}
sha512.__index = sha512

function sha512.new()
    local self = setmetatable({ context = ffi_new(ctx512) }, sha512)
    nettle.nettle_sha3_512_init(self.context)
    return self
end

function sha512:update(data)
    return nettle.nettle_sha3_512_update(self.context, #data, data)
end

function sha512:digest()
    nettle.nettle_sha3_512_digest(self.context, 64, buf512)
    return ffi_str(buf512, 64)
end

return {
    sha224     = sha224,
    sha256     = sha256,
    sha384     = sha384,
    sha512     = sha512
}

