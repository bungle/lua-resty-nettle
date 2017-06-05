local lib          = require "resty.nettle.library"
local ffi          = require "ffi"
local ffi_new      = ffi.new
local ffi_typeof   = ffi.typeof
local ffi_cdef     = ffi.cdef
local ffi_str      = ffi.string
local setmetatable = setmetatable

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

local uint8t = ffi_typeof "uint8_t[?]"
local ctx224 = ffi_typeof "SHA3_224_CTX[1]"
local ctx256 = ffi_typeof "SHA3_256_CTX[1]"
local ctx384 = ffi_typeof "SHA3_384_CTX[1]"
local ctx512 = ffi_typeof "SHA3_512_CTX[1]"
local buf224 = ffi_new(uint8t, 28)
local buf256 = ffi_new(uint8t, 32)
local buf384 = ffi_new(uint8t, 48)
local buf512 = ffi_new(uint8t, 64)

local hashes = {
    [224]       = {
        length  = 28,
        context = ctx224,
        buffer  = buf224,
        init    = lib.nettle_sha3_224_init,
        update  = lib.nettle_sha3_224_update,
        digest  = lib.nettle_sha3_224_digest
    },
    [256]       = {
        length  = 32,
        context = ctx256,
        buffer  = buf256,
        init    = lib.nettle_sha3_256_init,
        update  = lib.nettle_sha3_256_update,
        digest  = lib.nettle_sha3_256_digest
    },
    [384]       = {
        length  = 48,
        context = ctx384,
        buffer  = buf384,
        init    = lib.nettle_sha3_384_init,
        update  = lib.nettle_sha3_384_update,
        digest  = lib.nettle_sha3_384_digest
    },
    [512]       = {
        length  = 64,
        context = ctx512,
        buffer  = buf512,
        init    = lib.nettle_sha3_512_init,
        update  = lib.nettle_sha3_512_update,
        digest  = lib.nettle_sha3_512_digest
    }
}

local sha3 = {}
sha3.__index = sha3

function sha3:update(data, len)
    return self.hash.update(self.context, len or #data, data)
end

function sha3:digest()
    local hash = self.hash
    hash.digest(self.context, hash.length, hash.buffer)
    return ffi_str(hash.buffer, hash.length)
end

local function factory(hash)
    return setmetatable({ new = function()
        local ctx = ffi_new(hash.context)
        hash.init(ctx)
        return setmetatable({ context = ctx, hash = hash }, sha3)
    end }, {
        __call = function(_, data, len)
            local ctx = ffi_new(hash.context)
            hash.init(ctx)
            hash.update(ctx, len or #data, data)
            hash.digest(ctx, hash.length, hash.buffer)
            return ffi_str(hash.buffer, hash.length)
        end
    })
end

return setmetatable({
    sha224     = factory(hashes[224]),
    sha256     = factory(hashes[256]),
    sha384     = factory(hashes[384]),
    sha512     = factory(hashes[512])
}, { __call = function(_, bits, data, len)
    local hash = hashes[bits]
    if not hash then
        return nil, "the supported SHA3 algorithm output sizes are 224, 256, 384, and 512 bits"
    end
    local ctx = ffi_new(hash.context)
    hash.init(ctx)
    hash.update(ctx, len or #data, data)
    hash.digest(ctx, hash.length, hash.buffer)
    return ffi_str(hash.buffer, hash.length)
end })
