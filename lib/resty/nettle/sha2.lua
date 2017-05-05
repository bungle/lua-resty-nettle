require "resty.nettle.types.sha2"

local lib          = require "resty.nettle.library"
local ffi          = require "ffi"
local ffi_new      = ffi.new
local ffi_typeof   = ffi.typeof
local ffi_cdef     = ffi.cdef
local ffi_str      = ffi.string
local setmetatable = setmetatable


ffi_cdef[[
void nettle_sha224_init(struct sha256_ctx *ctx);
void nettle_sha224_digest(struct sha256_ctx *ctx, size_t length, uint8_t *digest);
void nettle_sha256_init(struct sha256_ctx *ctx);
void nettle_sha256_update(struct sha256_ctx *ctx, size_t length, const uint8_t *data);
void nettle_sha256_digest(struct sha256_ctx *ctx, size_t length, uint8_t *digest);
void nettle_sha384_init(struct sha512_ctx *ctx);
void nettle_sha384_digest(struct sha512_ctx *ctx, size_t length, uint8_t *digest);
void nettle_sha512_init(struct sha512_ctx *ctx);
void nettle_sha512_update(struct sha512_ctx *ctx, size_t length, const uint8_t *data);
void nettle_sha512_digest(struct sha512_ctx *ctx, size_t length, uint8_t *digest);
void nettle_sha512_224_init(struct sha512_ctx *ctx);
void nettle_sha512_224_digest(struct sha512_ctx *ctx, size_t length, uint8_t *digest);
void nettle_sha512_256_init(struct sha512_ctx *ctx);
void nettle_sha512_256_digest(struct sha512_ctx *ctx, size_t length, uint8_t *digest);
]]

local uint8t = ffi_typeof "uint8_t[?]"
local ctx256 = ffi_typeof "SHA256_CTX[1]"
local ctx512 = ffi_typeof "SHA512_CTX[1]"
local buf224 = ffi_new(uint8t, 28)
local buf256 = ffi_new(uint8t, 32)
local buf384 = ffi_new(uint8t, 48)
local buf512 = ffi_new(uint8t, 64)

local hashes = {
    sha224      = {
        length  = 28,
        context = ctx256,
        buffer  = buf224,
        init    = lib.nettle_sha224_init,
        update  = lib.nettle_sha256_update,
        digest  = lib.nettle_sha224_digest
    },
    sha256      = {
        length  = 32,
        context = ctx256,
        buffer  = buf256,
        init    = lib.nettle_sha256_init,
        update  = lib.nettle_sha256_update,
        digest  = lib.nettle_sha256_digest
    },
    sha384      = {
        length  = 48,
        context = ctx512,
        buffer  = buf384,
        init    = lib.nettle_sha384_init,
        update  = lib.nettle_sha512_update,
        digest  = lib.nettle_sha384_digest
    },
    sha512      = {
        length  = 64,
        context = ctx512,
        buffer  = buf512,
        init    = lib.nettle_sha512_init,
        update  = lib.nettle_sha512_update,
        digest  = lib.nettle_sha512_digest
    },
    sha512_224  = {
        length  = 28,
        context = ctx512,
        buffer  = buf224,
        init    = lib.nettle_sha512_224_init,
        update  = lib.nettle_sha512_update,
        digest  = lib.nettle_sha512_224_digest
    },
    sha512_256  = {
        length  = 32,
        context = ctx512,
        buffer  = buf256,
        init    = lib.nettle_sha512_256_init,
        update  = lib.nettle_sha512_update,
        digest  = lib.nettle_sha512_256_digest
    }
}

local sha2 = {}
sha2.__index = sha2

function sha2:update(data, len)
    return self.hash.update(self.context, len or #data, data)
end

function sha2:digest()
    local hash = self.hash
    hash.digest(self.context, hash.length, hash.buffer)
    return ffi_str(hash.buffer, hash.length)
end

local function factory(hash)
    return setmetatable({ new = function()
        local ctx = ffi_new(hash.context)
        hash.init(ctx)
        return setmetatable({ context = ctx, hash = hash }, sha2)
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
    sha224     = factory(hashes.sha224),
    sha256     = factory(hashes.sha256),
    sha384     = factory(hashes.sha384),
    sha512     = factory(hashes.sha512),
    sha512_224 = factory(hashes.sha512_224),
    sha512_256 = factory(hashes.sha512_256)
}, { __call = function(_, algorithm, data, len)
    local hash = hashes[algorithm:lower()]
    if not hash then
        return nil, "The supported SHA2 algorithms are SHA224, SHA256, SHA384, SHA512, SHA512_224, and SHA512_256."
    end
    local ctx = ffi_new(hash.context)
    hash.init(ctx)
    hash.update(ctx, len or #data, data)
    hash.digest(ctx, hash.length, hash.buffer)
    return ffi_str(hash.buffer, hash.length)
end })
