require "resty.nettle.types.aes"

local ffi        = require "ffi"
local ffi_new    = ffi.new
local ffi_typeof = ffi.typeof
local ffi_cdef   = ffi.cdef
local ffi_str    = ffi.string
local ceil       = math.ceil
local nettle     = require "resty.nettle"

ffi_cdef[[
void nettle_aes128_set_encrypt_key(struct aes128_ctx *ctx, const uint8_t *key);
void nettle_aes128_set_decrypt_key(struct aes128_ctx *ctx, const uint8_t *key);
void nettle_aes128_invert_key(struct aes128_ctx *dst, const struct aes128_ctx *src);
void nettle_aes128_encrypt(const struct aes128_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src);
void nettle_aes128_decrypt(const struct aes128_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src);
void nettle_aes192_set_encrypt_key(struct aes192_ctx *ctx, const uint8_t *key);
void nettle_aes192_set_decrypt_key(struct aes192_ctx *ctx, const uint8_t *key);
void nettle_aes192_invert_key(struct aes192_ctx *dst, const struct aes192_ctx *src);
void nettle_aes192_encrypt(const struct aes192_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src);
void nettle_aes192_decrypt(const struct aes192_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src);
void nettle_aes256_set_encrypt_key(struct aes256_ctx *ctx, const uint8_t *key);
void nettle_aes256_set_decrypt_key(struct aes256_ctx *ctx, const uint8_t *key);
void nettle_aes256_invert_key(struct aes256_ctx *dst, const struct aes256_ctx *src);
void nettle_aes256_encrypt(const struct aes256_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src);
void nettle_aes256_decrypt(const struct aes256_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src);
]]

local uint8t = ffi_typeof("uint8_t[?]")
local ctx128 = ffi_typeof("AES128_CTX[1]")
local ctx192 = ffi_typeof("AES192_CTX[1]")
local ctx256 = ffi_typeof("AES256_CTX[1]")

local aes128 = {}
aes128.__index = aes128

function aes128.new(key)
    local self = setmetatable({ context = ffi_new(ctx128), inverted = false }, aes128)
    nettle.nettle_aes128_set_encrypt_key(self.context, key)
    return self
end

function aes128:encrypt(src)
    if self.inverted then
        nettle.nettle_aes128_invert_key(self.context, self.context)
    end
    local len = ceil(#src / 16) * 16
    local dst = ffi_new(uint8t, len)
    nettle.nettle_aes128_encrypt(self.context, len, dst, src)
    return ffi_str(dst, len)
end

function aes128:decrypt(src)
    if not self.inverted then
        nettle.nettle_aes128_invert_key(self.context, self.context)
    end
    local len = #src
    local dst = ffi_new(uint8t, len)
    nettle.nettle_aes128_decrypt(self.context, len, dst, src)
    return ffi_str(dst)
end

local aes192 = {}
aes192.__index = aes192

function aes192.new(key)
    local self = setmetatable({ context = ffi_new(ctx192), inverted = false }, aes192)
    nettle.nettle_aes192_set_encrypt_key(self.context, key)
    return self
end

function aes192:encrypt(src)
    if self.inverted then
        nettle.nettle_aes192_invert_key(self.context, self.context)
    end
    local len = ceil(#src / 16) * 16
    local dst = ffi_new(uint8t, len)
    nettle.nettle_aes192_encrypt(self.context, len, dst, src)
    return ffi_str(dst, len)
end

function aes192:decrypt(src)
    if not self.inverted then
        nettle.nettle_aes192_invert_key(self.context, self.context)
    end
    local len = #src
    local dst = ffi_new(uint8t, len)
    nettle.nettle_aes192_decrypt(self.context, len, dst, src)
    return ffi_str(dst)
end

local aes256 = {}
aes256.__index = aes256

function aes256.new(key)
    local self = setmetatable({ context = ffi_new(ctx256), inverted = false }, aes256)
    nettle.nettle_aes256_set_encrypt_key(self.context, key)
    return self
end

function aes256:encrypt(src)
    if self.inverted then
        nettle.nettle_aes256_invert_key(self.context, self.context)
    end
    local len = ceil(#src / 16) * 16
    local dst = ffi_new(uint8t, len)
    nettle.nettle_aes256_encrypt(self.context, len, dst, src)
    return ffi_str(dst, len)
end

function aes256:decrypt(src)
    if not self.inverted then
        nettle.nettle_aes256_invert_key(self.context, self.context)
    end
    local len = #src
    local dst = ffi_new(uint8t, len)
    nettle.nettle_aes256_decrypt(self.context, len, dst, src)
    return ffi_str(dst)
end

return {
    aes128 = aes128,
    aes192 = aes192,
    aes256 = aes256
}
