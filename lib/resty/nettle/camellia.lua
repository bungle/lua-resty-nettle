require "resty.nettle.types.camellia"

local lib          = require "resty.nettle.library"
local ffi          = require "ffi"
local ffi_new      = ffi.new
local ffi_typeof   = ffi.typeof
local ffi_cdef     = ffi.cdef
local ffi_copy     = ffi.copy
local ffi_str      = ffi.string
local ceil         = math.ceil
local assert       = assert
local setmetatable = setmetatable

ffi_cdef[[
void nettle_camellia128_set_encrypt_key(struct camellia128_ctx *ctx, const uint8_t *key);
void nettle_camellia128_invert_key(struct camellia128_ctx *dst, const struct camellia128_ctx *src);
void nettle_camellia128_crypt(const struct camellia128_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src);
void nettle_camellia192_set_encrypt_key(struct camellia256_ctx *ctx, const uint8_t *key);
void nettle_camellia256_set_encrypt_key(struct camellia256_ctx *ctx, const uint8_t *key);
void nettle_camellia256_invert_key(struct camellia256_ctx *dst, const struct camellia256_ctx *src);
void nettle_camellia256_crypt(const struct camellia256_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src);
void nettle_gcm_camellia128_set_key(struct gcm_camellia128_ctx *ctx, const uint8_t *key);
void nettle_gcm_camellia128_update (struct gcm_camellia128_ctx *ctx, size_t length, const uint8_t *data);
void nettle_gcm_camellia128_set_iv (struct gcm_camellia128_ctx *ctx, size_t length, const uint8_t *iv);
void nettle_gcm_camellia128_encrypt(struct gcm_camellia128_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src);
void nettle_gcm_camellia128_decrypt(struct gcm_camellia128_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src);
void nettle_gcm_camellia128_digest (struct gcm_camellia128_ctx *ctx, size_t length, uint8_t *digest);
void nettle_gcm_camellia256_set_key(struct gcm_camellia256_ctx *ctx, const uint8_t *key);
void nettle_gcm_camellia256_update (struct gcm_camellia256_ctx *ctx, size_t length, const uint8_t *data);
void nettle_gcm_camellia256_set_iv (struct gcm_camellia256_ctx *ctx, size_t length, const uint8_t *iv);
void nettle_gcm_camellia256_encrypt(struct gcm_camellia256_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src);
void nettle_gcm_camellia256_decrypt(struct gcm_camellia256_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src);
void nettle_gcm_camellia256_digest (struct gcm_camellia256_ctx *ctx, size_t length, uint8_t *digest);
]]

local uint8t = ffi_typeof "uint8_t[?]"

local ciphers = {
    ecb = {
        [128] = {
            setkey  = lib.nettle_camellia128_set_encrypt_key,
            invert  = lib.nettle_camellia128_invert_key,
            encrypt = lib.nettle_camellia128_crypt,
            decrypt = lib.nettle_camellia128_crypt,
            context = ffi_typeof "CAMELLIA128_CTX[1]"
        },
        [192] = {
            setkey  = lib.nettle_camellia192_set_encrypt_key,
            invert  = lib.nettle_camellia256_invert_key,
            encrypt = lib.nettle_camellia256_crypt,
            decrypt = lib.nettle_camellia256_crypt,
            context = ffi_typeof "CAMELLIA256_CTX[1]"
        },
        [256] = {
            setkey  = lib.nettle_camellia256_set_encrypt_key,
            invert  = lib.nettle_camellia256_invert_key,
            encrypt = lib.nettle_camellia256_crypt,
            decrypt = lib.nettle_camellia256_crypt,
            context = ffi_typeof "CAMELLIA256_CTX[1]"
        }
    },
    gcm = {
        iv_size  = 12,
        [128] = {
            setkey  = lib.nettle_gcm_camellia128_set_key,
            setiv   = lib.nettle_gcm_camellia128_set_iv,
            update  = lib.nettle_gcm_camellia128_update,
            encrypt = lib.nettle_gcm_camellia128_encrypt,
            decrypt = lib.nettle_gcm_camellia128_decrypt,
            digest  = lib.nettle_gcm_camellia128_digest,
            context = ffi_typeof "GCM_CAMELLIA128_CTX[1]"
        },
        [256] = {
            setkey  = lib.nettle_gcm_camellia256_set_key,
            setiv   = lib.nettle_gcm_camellia256_set_iv,
            update  = lib.nettle_gcm_camellia256_update,
            encrypt = lib.nettle_gcm_camellia256_encrypt,
            decrypt = lib.nettle_gcm_camellia256_decrypt,
            digest  = lib.nettle_gcm_camellia256_digest,
            context = ffi_typeof "GCM_CAMELLIA256_CTX[1]"
        }        
    }
}
local dgt = ffi_new(uint8t, 16)

local camellia = {}
camellia.__index = camellia

function camellia.new(key, mode, iv, ad)
    local len = #key
    assert(len == 16 or len == 24 or len == 32, "The Camellia supported key sizes are 128, 192, and 256 bits.")
    mode = (mode or "ecb"):lower()
    local config = ciphers[mode]
    assert(config, "The Camellia supported modes are ECB, and GCM.")
    local bits = len * 8
    local cipher = config[bits]
    local context = ffi_new(cipher.context)
    cipher.setkey(context, key)
    local iv_size = config.iv_size
    if iv_size then
        iv = iv or ""
        assert(#iv == iv_size, "The Camellia-" .. mode:upper() .. " supported initialization vector size is " .. (iv_size * 8) .. " bits.")
        cipher.setiv(context, iv_size, iv)
    end
    if ad and cipher.update then
        cipher.update(context, #ad, ad)
    end
    return setmetatable({
        context = context,
        cipher  = cipher }, camellia)
end

function camellia:encrypt(src, len)
    local cipher  = self.cipher
    local context = self.context
    if cipher.invert and self.inverted then
        cipher.invert(context, context)
        self.inverted = nil
    end
    len = len or #src
    if cipher.digest then
        local dst = ffi_new(uint8t, len)
        cipher.encrypt(context, len, dst, src)
        cipher.digest(context, 16, dgt)
        return ffi_str(dst, len), ffi_str(dgt, 16)
    end
    local dln = ceil(len / 16) * 16
    local dst = ffi_new(uint8t, dln)
    ffi_copy(dst, src, len)
    cipher.encrypt(context, dln, dst, dst)
    return ffi_str(dst, dln)
end

function camellia:decrypt(src, len)
    local cipher  = self.cipher
    local context = self.context
    if cipher.invert and not self.inverted then
        cipher.invert(context, context)
        self.inverted = true
    end
    len = len or #src
    if cipher.digest then
        local dst = ffi_new(uint8t, len)
        cipher.decrypt(context, len, dst, src)
        cipher.digest(context, 16, dgt)
        return ffi_str(dst, len), ffi_str(dgt, 16)
    end
    local dln = ceil(len / 16) * 16
    local dst = ffi_new(uint8t, dln)
    cipher.decrypt(context, dln, dst, src)
    return ffi_str(dst, len)
end

return camellia
