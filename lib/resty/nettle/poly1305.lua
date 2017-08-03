require "resty.nettle.types.poly1305"

local lib          = require "resty.nettle.library"
local ffi          = require "ffi"
local ffi_new      = ffi.new
local ffi_typeof   = ffi.typeof
local ffi_cdef     = ffi.cdef
local ffi_str      = ffi.string
local setmetatable = setmetatable

ffi_cdef[[
void nettle_poly1305_aes_set_key(struct poly1305_aes_ctx *ctx, const uint8_t *key);
void nettle_poly1305_aes_set_nonce(struct poly1305_aes_ctx *ctx, const uint8_t *nonce);
void nettle_poly1305_aes_update(struct poly1305_aes_ctx *ctx, size_t length, const uint8_t *data);
void nettle_poly1305_aes_digest(struct poly1305_aes_ctx *ctx, size_t length, uint8_t *digest);
]]

local ctxply = ffi_typeof "NETTLE_POLY1305_AES_CTX[1]"
local buf128 = ffi_new("uint8_t[?]", 16)

local poly1305 = setmetatable({}, {
    __call = function(_, key, nonce, data, len)
        local context = ffi_new(ctxply)
        lib.nettle_poly1305_aes_set_key(context, key)
        if nonce then
            lib.nettle_poly1305_aes_set_nonce(context, #nonce, nonce)
        end
        lib.nettle_poly1305_aes_update(context, len or #data, data)
        lib.nettle_poly1305_aes_digest(context, 16, buf128)
        return ffi_str(buf128, 16)
    end
})
poly1305.__index = poly1305

function poly1305.new(key, nonce)
    local self = setmetatable({ context = ffi_new(ctxply) }, poly1305)
    lib.nettle_poly1305_aes_set_key(self.context, key)
    if nonce then
        lib.nettle_poly1305_aes_set_nonce(self.context, #nonce, nonce)
    end
    return self
end

function poly1305:update(data, len)
    return lib.nettle_poly1305_aes_update(self.context, len or #data, data)
end

function poly1305:digest()
    lib.nettle_poly1305_aes_digest(self.context, 16, buf128)
    return ffi_str(buf128, 16)
end

return poly1305
