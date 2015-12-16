require "resty.nettle.types.camellia"

local ffi          = require "ffi"
local ffi_new      = ffi.new
local ffi_typeof   = ffi.typeof
local ffi_cdef     = ffi.cdef
local ffi_str      = ffi.string
local ceil         = math.ceil
local assert       = assert
local setmetatable = setmetatable
local nettle       = require "resty.nettle"

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
            setkey  = nettle.nettle_camellia128_set_encrypt_key,
            invert  = nettle.nettle_camellia128_invert_key,
            encrypt = nettle.nettle_camellia128_crypt,
            decrypt = nettle.nettle_camellia128_crypt,
            context = ffi_typeof "CAMELLIA128_CTX[1]"
        },
        [192] = {
            setkey  = nettle.nettle_camellia192_set_encrypt_key,
            invert  = nettle.nettle_camellia256_invert_key,
            encrypt = nettle.nettle_camellia256_crypt,
            decrypt = nettle.nettle_camellia256_crypt,
            context = ffi_typeof "CAMELLIA256_CTX[1]"
        },
        [256] = {
            setkey  = nettle.nettle_camellia256_set_encrypt_key,
            invert  = nettle.nettle_camellia256_invert_key,
            encrypt = nettle.nettle_camellia256_crypt,
            decrypt = nettle.nettle_camellia256_crypt,
            context = ffi_typeof "CAMELLIA256_CTX[1]"
        }
    },
    gcm = {
        iv_size  = 12,
        [128] = {
            setkey  = nettle.nettle_gcm_camellia128_set_key,
            setiv   = nettle.nettle_gcm_camellia128_set_iv,
            update  = nettle.nettle_gcm_camellia128_update,
            encrypt = nettle.nettle_gcm_camellia128_encrypt,
            decrypt = nettle.nettle_gcm_camellia128_decrypt,
            digest  = nettle.nettle_gcm_camellia128_digest,
            context = ffi_typeof "GCM_CAMELLIA128_CTX[1]"
        },
        [256] = {
            setkey  = nettle.nettle_gcm_camellia256_set_key,
            setiv   = nettle.nettle_gcm_camellia256_set_iv,
            update  = nettle.nettle_gcm_camellia256_update,
            encrypt = nettle.nettle_gcm_camellia256_encrypt,
            decrypt = nettle.nettle_gcm_camellia256_decrypt,
            digest  = nettle.nettle_gcm_camellia256_digest,
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

function camellia:encrypt(src)
    local cipher  = self.cipher
    local context = self.context
    if cipher.invert and self.inverted then
        cipher.invert(context, context)
        self.inverted = nil
    end
    if cipher.digest then
        local len = #src
        local dst = ffi_new(uint8t, len)
        cipher.encrypt(context, len, dst, src)
        cipher.digest(context, 16, dgt)
        return ffi_str(dst, len), ffi_str(dgt, 16)
    end
    local len = ceil(#src / 16) * 16
    local dst = ffi_new(uint8t, len)
    cipher.encrypt(context, len, dst, src)
    return ffi_str(dst, len)
end

function camellia:decrypt(src)
    local cipher  = self.cipher
    local context = self.context
    if cipher.invert and not self.inverted then
        cipher.invert(context, context)
        self.inverted = true
    end
    if cipher.digest then
        local len = #src
        local dst = ffi_new(uint8t, len)
        cipher.decrypt(context, len, dst, src)
        cipher.digest(context, 16, dgt)
        return ffi_str(dst, len), ffi_str(dgt, 16)
    end
    local len = ceil(#src / 16) * 16
    local dst = ffi_new(uint8t, len + 1)
    cipher.decrypt(context, len, dst, src)
    return ffi_str(dst)
end

return camellia
