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

local ciphers = {
    [128] = {
        setkey  = nettle.nettle_aes128_set_encrypt_key,
        invert  = nettle.nettle_aes128_invert_key,
        encrypt = nettle.nettle_aes128_encrypt,
        decrypt = nettle.nettle_aes128_decrypt,
        context = ffi_typeof("AES128_CTX[1]")
    },
    [192] = {
        setkey  = nettle.nettle_aes192_set_encrypt_key,
        invert  = nettle.nettle_aes192_invert_key,
        encrypt = nettle.nettle_aes192_encrypt,
        decrypt = nettle.nettle_aes192_decrypt,
        context = ffi_typeof("AES192_CTX[1]")
    },
    [256] = {
        setkey  = nettle.nettle_aes256_set_encrypt_key,
        invert  = nettle.nettle_aes256_invert_key,
        encrypt = nettle.nettle_aes256_encrypt,
        decrypt = nettle.nettle_aes256_decrypt,
        context = ffi_typeof("AES256_CTX[1]")
    }
}

local aes = {}
aes.__index = aes

function aes.new(bits, key, options)
    local cipher = ciphers[bits]
    options = options or {}
    local self = setmetatable({
        context  = ffi_new(cipher.context),
        inverted = false,
        mode     = options.mode or "ecb",
        bits     = bits
    }, aes)
    if self.mode == "cbc" then
        self.iv = options.iv or ""
    elseif self.mode == "ctr" then
        self.ctr = options.ctr or ""
    end
    cipher.setkey(self.context, key)
    return self
end

function aes:encrypt(src)
    local cipher = ciphers[self.bits]
    if self.inverted then
        self.cipher.invert(self.context, self.context)
    end
    if self.mode == "ctr" then
        local len = #src
        local dst = ffi_new(uint8t, len)
        local ctr = ffi_new(uint8t, 16)
        ffi_copy(ctr, self.ctr, 16)
        nettle.nettle_ctr_crypt(self.context, cipher.encrypt, 16, ctr, len, dst, src)
        return ffi_str(dst, len)
    end
    local len = ceil(#src / 16) * 16
    local dst = ffi_new(uint8t, len)
    if self.mode == "cbc" then
        local iv = ffi_new(uint8t, len)
        ffi_copy(iv, self.iv, 16)
        nettle.nettle_cbc_encrypt(self.context, cipher.encrypt, 16, iv, len, dst, src)
    else
        cipher.encrypt(self.context, len, dst, src)
    end
    return ffi_str(dst, len)
end

function aes:decrypt(src)
    local cipher = ciphers[self.bits]
    if not self.inverted and self.mode ~= "ctr" then
        cipher.invert(self.context, self.context)
    end
    if self.mode == "ctr" then
        local len = #src
        local dst = ffi_new(uint8t, len)
        local ctr = ffi_new(uint8t, 16)
        ffi_copy(ctr, self.ctr, 16)
        nettle.nettle_ctr_crypt(self.context, cipher.encrypt, 16, ctr, len, dst, src)
        return ffi_str(dst, len)
    end
    local len = ceil(#src / 16) * 16
    local dst = ffi_new(uint8t, len + 1)
    if self.mode == "cbc" then
        local iv = ffi_new(uint8t, 16)
        ffi_copy(iv, self.iv, 16)
        nettle.nettle_cbc_decrypt(self.context, cipher.decrypt, 16, iv, len, dst, src)
    else
        cipher.decrypt(self.context, len, dst, src)
    end
    return ffi_str(dst)
end

return {
    aes128 = { new = function(key, options) return aes.new(128, key, options) end },
    aes192 = { new = function(key, options) return aes.new(192, key, options) end },
    aes256 = { new = function(key, options) return aes.new(256, key, options) end }
}
