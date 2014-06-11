require "resty.nettle.types.aes"

local ffi        = require "ffi"
local ffi_new    = ffi.new
local ffi_typeof = ffi.typeof
local ffi_cdef   = ffi.cdef
local ffi_copy   = ffi.copy
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
void nettle_cbc_encrypt(const void *ctx, nettle_cipher_func *f, size_t block_size, uint8_t *iv, size_t length, uint8_t *dst, const uint8_t *src);
void nettle_cbc_decrypt(const void *ctx, nettle_cipher_func *f, size_t block_size, uint8_t *iv, size_t length, uint8_t *dst, const uint8_t *src);
void nettle_ctr_crypt(const void *ctx, nettle_cipher_func *f, size_t block_size, uint8_t *ctr, size_t length, uint8_t *dst, const uint8_t *src);
]]

local uint8t = ffi_typeof("uint8_t[?]")
local ctx128 = ffi_typeof("AES128_CTX[1]")
local ctx192 = ffi_typeof("AES192_CTX[1]")
local ctx256 = ffi_typeof("AES256_CTX[1]")

local aes128 = {}
aes128.__index = aes128

function aes128.new(key, options)
    options = options or {}
    local self = setmetatable({
        context  = ffi_new(ctx128),
        inverted = false,
        mode     = options.mode or "ecb",
    }, aes128)
    if self.mode == "cbc" then
        self.iv = options.iv or ""
    elseif self.mode == "ctr" then
        self.ctr = options.ctr or ""
    end
    nettle.nettle_aes128_set_encrypt_key(self.context, key)
    return self
end

function aes128:encrypt(src)
    if self.inverted then
        nettle.nettle_aes128_invert_key(self.context, self.context)
    end
    local len = ceil(#src / 16) * 16
    local dst = ffi_new(uint8t, len)
    if self.mode == "cbc" then
        local iv = ffi_new(uint8t, len)
        ffi_copy(iv, self.iv, 16)
        nettle.nettle_cbc_encrypt(self.context, nettle.nettle_aes128_encrypt, 16, iv, len, dst, src)
    elseif self.mode == "ctr" then
        local ctr = ffi_new(uint8t, 16)
        ffi_copy(ctr, self.ctr, 16)
        nettle.nettle_ctr_crypt(self.context, nettle.nettle_aes128_encrypt, 16, ctr, len, dst, src)
    else
        nettle.nettle_aes128_encrypt(self.context, len, dst, src)
    end
    return ffi_str(dst, len)
end

function aes128:decrypt(src)
    if not self.inverted and self.mode ~= "ctr" then
        nettle.nettle_aes128_invert_key(self.context, self.context)
    end
    local len = ceil(#src / 16) * 16
    local dst = ffi_new(uint8t, len + 1)
    if self.mode == "cbc" then
        local iv = ffi_new(uint8t, 16)
        ffi_copy(iv, self.iv, 16)
        nettle.nettle_cbc_decrypt(self.context, nettle.nettle_aes128_decrypt, 16, iv, len, dst, src)
    elseif self.mode == "ctr" then
        local ctr = ffi_new(uint8t, 16)
        ffi_copy(ctr, self.ctr, 16)
        nettle.nettle_ctr_crypt(self.context, nettle.nettle_aes128_encrypt, 16, ctr, len, dst, src)
    else
        nettle.nettle_aes128_decrypt(self.context, len, dst, src)
    end
    return ffi_str(dst)
end

local aes192 = {}
aes192.__index = aes192

function aes192.new(key, options)
    options = options or {}
    local self = setmetatable({
        context  = ffi_new(ctx192),
        inverted = false,
        mode     = options.mode or "ecb",
    }, aes192)
    if self.mode == "cbc" then
        self.iv = options.iv or ""
    elseif self.mode == "ctr" then
        self.ctr = options.ctr or ""
    end
    nettle.nettle_aes192_set_encrypt_key(self.context, key)
    return self
end

function aes192:encrypt(src)
    if self.inverted then
        nettle.nettle_aes192_invert_key(self.context, self.context)
    end
    local len = ceil(#src / 16) * 16
    local dst = ffi_new(uint8t, len)
    if self.mode == "cbc" then
        local iv = ffi_new(uint8t, len)
        ffi_copy(iv, self.iv, 16)
        nettle.nettle_cbc_encrypt(self.context, nettle.nettle_aes192_encrypt, 16, iv, len, dst, src)
    elseif self.mode == "ctr" then
        local ctr = ffi_new(uint8t, 16)
        ffi_copy(ctr, self.ctr, 16)
        nettle.nettle_ctr_crypt(self.context, nettle.nettle_aes192_encrypt, 16, ctr, len, dst, src)
    else
        nettle.nettle_aes192_encrypt(self.context, len, dst, src)
    end
    return ffi_str(dst, len)
end

function aes192:decrypt(src)
    if not self.inverted and self.mode ~= "ctr" then
        nettle.nettle_aes192_invert_key(self.context, self.context)
    end
    local len = #src
    local dst = ffi_new(uint8t, len + 1)
    if self.mode == "cbc" then
        local iv = ffi_new(uint8t, 16)
        ffi_copy(iv, self.iv, 16)
        nettle.nettle_cbc_decrypt(self.context, nettle.nettle_aes192_decrypt, 16, iv, len, dst, src)
    elseif self.mode == "ctr" then
        local ctr = ffi_new(uint8t, 16)
        ffi_copy(ctr, self.ctr, 16)
        nettle.nettle_ctr_crypt(self.context, nettle.nettle_aes192_encrypt, 16, ctr, len, dst, src)
    else
        nettle.nettle_aes192_decrypt(self.context, len, dst, src)
    end
    return ffi_str(dst)
end

local aes256 = {}
aes256.__index = aes256

function aes256.new(key, options)
    options = options or {}
    local self = setmetatable({
        context  = ffi_new(ctx256),
        inverted = false,
        mode     = options.mode or "ecb",
    }, aes256)
    if self.mode == "cbc" then
        self.iv = options.iv or ""
    elseif self.mode == "ctr" then
        self.ctr = options.ctr or ""
    end
    nettle.nettle_aes256_set_encrypt_key(self.context, key)
    return self
end

function aes256:encrypt(src)
    if self.inverted then
        nettle.nettle_aes256_invert_key(self.context, self.context)
    end
    local len = ceil(#src / 16) * 16
    local dst = ffi_new(uint8t, len)
    if self.mode == "cbc" then
        local iv = ffi_new(uint8t, len)
        ffi_copy(iv, self.iv, 16)
        nettle.nettle_cbc_encrypt(self.context, nettle.nettle_aes256_encrypt, 16, iv, len, dst, src)
    elseif self.mode == "ctr" then
        local ctr = ffi_new(uint8t, 16)
        ffi_copy(ctr, self.ctr, 16)
        nettle.nettle_ctr_crypt(self.context, nettle.nettle_aes256_encrypt, 16, ctr, len, dst, src)
    else
        nettle.nettle_aes256_encrypt(self.context, len, dst, src)
    end
    return ffi_str(dst, len)
end

function aes256:decrypt(src)
    if not self.inverted and self.mode ~= "ctr" then
        nettle.nettle_aes256_invert_key(self.context, self.context)
    end
    local len = #src
    local dst = ffi_new(uint8t, len + 1)
    if self.mode == "cbc" then
        local iv = ffi_new(uint8t, 16)
        ffi_copy(iv, self.iv, 16)
        nettle.nettle_cbc_decrypt(self.context, nettle.nettle_aes256_decrypt, 16, iv, len, dst, src)
    elseif self.mode == "ctr" then
        local ctr = ffi_new(uint8t, 16)
        ffi_copy(ctr, self.ctr, 16)
        nettle.nettle_ctr_crypt(self.context, nettle.nettle_aes256_encrypt, 16, ctr, len, dst, src)
    else
        nettle.nettle_aes256_decrypt(self.context, len, dst, src)
    end
    return ffi_str(dst)
end

return {
    aes128 = aes128,
    aes192 = aes192,
    aes256 = aes256
}
