require "resty.nettle.types.aes"

local ffi          = require "ffi"
local ffi_new      = ffi.new
local ffi_typeof   = ffi.typeof
local ffi_cdef     = ffi.cdef
local ffi_copy     = ffi.copy
local ffi_str      = ffi.string
local ceil         = math.ceil
local huge         = math.huge
local type         = type
local assert       = assert
local setmetatable = setmetatable
local nettle       = require "resty.nettle"

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
void nettle_eax_aes128_set_key(struct eax_aes128_ctx *ctx, const uint8_t *key);
void nettle_eax_aes128_set_nonce(struct eax_aes128_ctx *ctx, size_t length, const uint8_t *iv);
void nettle_eax_aes128_update(struct eax_aes128_ctx *ctx, size_t length, const uint8_t *data);
void nettle_eax_aes128_encrypt(struct eax_aes128_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src);
void nettle_eax_aes128_decrypt(struct eax_aes128_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src);
void nettle_eax_aes128_digest (struct eax_aes128_ctx *ctx, size_t length, uint8_t *digest);
void nettle_gcm_aes128_set_key(struct gcm_aes128_ctx *ctx, const uint8_t *key);
void nettle_gcm_aes128_update (struct gcm_aes128_ctx *ctx, size_t length, const uint8_t *data);
void nettle_gcm_aes128_set_iv (struct gcm_aes128_ctx *ctx, size_t length, const uint8_t *iv);
void nettle_gcm_aes128_encrypt(struct gcm_aes128_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src);
void nettle_gcm_aes128_decrypt(struct gcm_aes128_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src);
void nettle_gcm_aes128_digest (struct gcm_aes128_ctx *ctx, size_t length, uint8_t *digest);
void nettle_gcm_aes192_set_key(struct gcm_aes192_ctx *ctx, const uint8_t *key);
void nettle_gcm_aes192_update (struct gcm_aes192_ctx *ctx, size_t length, const uint8_t *data);
void nettle_gcm_aes192_set_iv (struct gcm_aes192_ctx *ctx, size_t length, const uint8_t *iv);
void nettle_gcm_aes192_encrypt(struct gcm_aes192_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src);
void nettle_gcm_aes192_decrypt(struct gcm_aes192_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src);
void nettle_gcm_aes192_digest (struct gcm_aes192_ctx *ctx, size_t length, uint8_t *digest);
void nettle_gcm_aes256_set_key(struct gcm_aes256_ctx *ctx, const uint8_t *key);
void nettle_gcm_aes256_update (struct gcm_aes256_ctx *ctx, size_t length, const uint8_t *data);
void nettle_gcm_aes256_set_iv (struct gcm_aes256_ctx *ctx, size_t length, const uint8_t *iv);
void nettle_gcm_aes256_encrypt(struct gcm_aes256_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src);
void nettle_gcm_aes256_decrypt(struct gcm_aes256_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src);
void nettle_gcm_aes256_digest (struct gcm_aes256_ctx *ctx, size_t length, uint8_t *digest);
void nettle_ccm_aes128_set_key(struct ccm_aes128_ctx *ctx, const uint8_t *key);
void nettle_ccm_aes128_set_nonce(struct ccm_aes128_ctx *ctx, size_t length, const uint8_t *nonce, size_t authlen, size_t msglen, size_t taglen);
void nettle_ccm_aes128_update (struct ccm_aes128_ctx *ctx, size_t length, const uint8_t *data);
void nettle_ccm_aes128_encrypt(struct ccm_aes128_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src);
void nettle_ccm_aes128_decrypt(struct ccm_aes128_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src);
void nettle_ccm_aes128_digest(struct ccm_aes128_ctx *ctx, size_t length, uint8_t *digest);
void nettle_ccm_aes192_set_key(struct ccm_aes192_ctx *ctx, const uint8_t *key);
void nettle_ccm_aes192_set_nonce(struct ccm_aes192_ctx *ctx, size_t length, const uint8_t *nonce, size_t authlen, size_t msglen, size_t taglen);
void nettle_ccm_aes192_update(struct ccm_aes192_ctx *ctx, size_t length, const uint8_t *data);
void nettle_ccm_aes192_encrypt(struct ccm_aes192_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src);
void nettle_ccm_aes192_decrypt(struct ccm_aes192_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src);
void nettle_ccm_aes192_digest(struct ccm_aes192_ctx *ctx, size_t length, uint8_t *digest);
void nettle_ccm_aes256_set_key(struct ccm_aes256_ctx *ctx, const uint8_t *key);
void nettle_ccm_aes256_set_nonce(struct ccm_aes256_ctx *ctx, size_t length, const uint8_t *nonce, size_t authlen, size_t msglen, size_t taglen);
void nettle_ccm_aes256_update(struct ccm_aes256_ctx *ctx, size_t length, const uint8_t *data);
void nettle_ccm_aes256_encrypt(struct ccm_aes256_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src);
void nettle_ccm_aes256_decrypt(struct ccm_aes256_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src);
void nettle_ccm_aes256_digest(struct ccm_aes256_ctx *ctx, size_t length, uint8_t *digest);
]]

local uint8t = ffi_typeof "uint8_t[?]"

local ciphers = {
    ecb = {
        [128] = {
            setkey  = nettle.nettle_aes128_set_encrypt_key,
            invert  = nettle.nettle_aes128_invert_key,
            encrypt = nettle.nettle_aes128_encrypt,
            decrypt = nettle.nettle_aes128_decrypt,
            context = ffi_typeof "AES128_CTX[1]"
        },
        [192] = {
            setkey  = nettle.nettle_aes192_set_encrypt_key,
            invert  = nettle.nettle_aes192_invert_key,
            encrypt = nettle.nettle_aes192_encrypt,
            decrypt = nettle.nettle_aes192_decrypt,
            context = ffi_typeof "AES192_CTX[1]"
        },
        [256] = {
            setkey  = nettle.nettle_aes256_set_encrypt_key,
            invert  = nettle.nettle_aes256_invert_key,
            encrypt = nettle.nettle_aes256_encrypt,
            decrypt = nettle.nettle_aes256_decrypt,
            context = ffi_typeof "AES256_CTX[1]"
        }
    },
    cbc = {
        iv_size  = 16,
        [128] = {
            setkey  = nettle.nettle_aes128_set_encrypt_key,
            invert  = nettle.nettle_aes128_invert_key,
            encrypt = nettle.nettle_cbc_encrypt,
            decrypt = nettle.nettle_cbc_decrypt,
            cipher  = {
                encrypt = nettle.nettle_aes128_encrypt,
                decrypt = nettle.nettle_aes128_decrypt
            },
            context = ffi_typeof "AES128_CTX[1]"
        },
        [192] = {
            setkey  = nettle.nettle_aes192_set_encrypt_key,
            invert  = nettle.nettle_aes192_invert_key,
            encrypt = nettle.nettle_cbc_encrypt,
            decrypt = nettle.nettle_cbc_decrypt,
            cipher  = {
                encrypt = nettle.nettle_aes192_encrypt,
                decrypt = nettle.nettle_aes192_decrypt
            },
            context = ffi_typeof "AES192_CTX[1]"
        },
        [256] = {
            setkey  = nettle.nettle_aes256_set_encrypt_key,
            invert  = nettle.nettle_aes256_invert_key,
            encrypt = nettle.nettle_cbc_encrypt,
            decrypt = nettle.nettle_cbc_decrypt,
            cipher  = {
                encrypt = nettle.nettle_aes256_encrypt,
                decrypt = nettle.nettle_aes256_decrypt
            },
            context = ffi_typeof "AES256_CTX[1]"
        }
    },
    ctr = {
        iv_size  = 16,
        [128] = {
            setkey  = nettle.nettle_aes128_set_encrypt_key,
            encrypt  = nettle.nettle_ctr_crypt,
            decrypt  = nettle.nettle_ctr_crypt,
            cipher  = {
                encrypt = nettle.nettle_aes128_encrypt,
                decrypt = nettle.nettle_aes128_encrypt
            },
            context = ffi_typeof "AES128_CTX[1]"
        },
        [192] = {
            setkey  = nettle.nettle_aes192_set_encrypt_key,
            encrypt  = nettle.nettle_ctr_crypt,
            decrypt  = nettle.nettle_ctr_crypt,
            cipher  = {
                encrypt = nettle.nettle_aes192_encrypt,
                decrypt = nettle.nettle_aes192_encrypt
            },
            context = ffi_typeof "AES192_CTX[1]"
        },
        [256] = {
            setkey  = nettle.nettle_aes256_set_encrypt_key,
            encrypt = nettle.nettle_ctr_crypt,
            decrypt = nettle.nettle_ctr_crypt,
            cipher  = {
                encrypt = nettle.nettle_aes256_encrypt,
                decrypt = nettle.nettle_aes256_encrypt
            },
            context = ffi_typeof "AES256_CTX[1]"
        }
    },
    eax = {
        iv_size  = huge,
        [128] = {
            setkey  = nettle.nettle_eax_aes128_set_key,
            setiv   = nettle.nettle_eax_aes128_set_nonce,
            update  = nettle.nettle_eax_aes128_update,
            encrypt = nettle.nettle_eax_aes128_encrypt,
            decrypt = nettle.nettle_eax_aes128_decrypt,
            digest  = nettle.nettle_eax_aes128_digest,
            context = ffi_typeof "EAX_AES128_CTX[1]"
        }
    },
    gcm = {
        iv_size  = 12,
        [128] = {
            setkey  = nettle.nettle_gcm_aes128_set_key,
            setiv   = nettle.nettle_gcm_aes128_set_iv,
            update  = nettle.nettle_gcm_aes128_update,
            encrypt = nettle.nettle_gcm_aes128_encrypt,
            decrypt = nettle.nettle_gcm_aes128_decrypt,
            digest  = nettle.nettle_gcm_aes128_digest,
            context = ffi_typeof "GCM_AES128_CTX[1]"
        },
        [192] = {
            setkey  = nettle.nettle_gcm_aes192_set_key,
            setiv   = nettle.nettle_gcm_aes192_set_iv,
            update  = nettle.nettle_gcm_aes192_update,
            encrypt = nettle.nettle_gcm_aes192_encrypt,
            decrypt = nettle.nettle_gcm_aes192_decrypt,
            digest  = nettle.nettle_gcm_aes192_digest,
            context = ffi_typeof "GCM_AES192_CTX[1]"
        },
        [256] = {
            setkey  = nettle.nettle_gcm_aes256_set_key,
            setiv   = nettle.nettle_gcm_aes256_set_iv,
            update  = nettle.nettle_gcm_aes256_update,
            encrypt = nettle.nettle_gcm_aes256_encrypt,
            decrypt = nettle.nettle_gcm_aes256_decrypt,
            digest  = nettle.nettle_gcm_aes256_digest,
            context = ffi_typeof "GCM_AES256_CTX[1]"
        }        
    },
    ccm = {
        iv_size  = { 7, 14 },
        [128] = {
            setkey  = nettle.nettle_ccm_aes128_set_key,
            setiv   = nettle.nettle_ccm_aes128_set_nonce,
            update  = nettle.nettle_ccm_aes128_update,
            encrypt = nettle.nettle_ccm_aes128_encrypt,
            decrypt = nettle.nettle_ccm_aes128_decrypt,
            digest  = nettle.nettle_ccm_aes128_digest,
            context = ffi_typeof "CCM_AES128_CTX[1]"
        },
        [192] = {
            setkey  = nettle.nettle_ccm_aes192_set_key,
            setiv   = nettle.nettle_ccm_aes192_set_nonce,
            update  = nettle.nettle_ccm_aes192_update,
            encrypt = nettle.nettle_ccm_aes192_encrypt,
            decrypt = nettle.nettle_ccm_aes192_decrypt,
            digest  = nettle.nettle_ccm_aes192_digest,
            context = ffi_typeof "CCM_AES192_CTX[1]"
        },
        [256] = {
            setkey  = nettle.nettle_ccm_aes256_set_key,
            setiv   = nettle.nettle_ccm_aes256_set_nonce,
            update  = nettle.nettle_ccm_aes256_update,
            encrypt = nettle.nettle_ccm_aes256_encrypt,
            decrypt = nettle.nettle_ccm_aes256_decrypt,
            digest  = nettle.nettle_ccm_aes256_digest,
            context = ffi_typeof "CCM_AES256_CTX[1]"
        }        
    }
}
local dgt = ffi_new(uint8t, 16)

local ccm = {}
ccm.__index = ccm

function ccm:encrypt(src, len)
    local cipher  = self.cipher
    local context = self.context
    local iv      = self.iv
    local ad      = self.ad or ""
    local lad     = #ad
    local len     = len or #src
    cipher.setiv(context, #iv, iv, lad, len, 16)
    if ad then cipher.update(context, lad, ad) end
    local dst = ffi_new(uint8t, len)
    cipher.encrypt(context, len, dst, src)
    cipher.digest(context, 16, dgt)
    return ffi_str(dst, len), ffi_str(dgt, 16)
end

function ccm:decrypt(src, len)
    local cipher  = self.cipher
    local context = self.context
    local iv      = self.iv
    local ad      = self.ad or ""
    local lad     = #ad
    local len     = len or #src
    cipher.setiv(context, #iv, iv, lad, len, 16)
    if ad then cipher.update(context, lad, ad) end
    local dst = ffi_new(uint8t, len)
    cipher.decrypt(context, len, dst, src)
    cipher.digest(context, 16, dgt)
    return ffi_str(dst, len), ffi_str(dgt, 16)
end

local aes = {}
aes.__index = aes

function aes.new(key, mode, iv, ad)
    local len = #key
    assert(len == 16 or len == 24 or len == 32, "The AES supported key sizes are 128, 192, and 256 bits.")
    mode = (mode or "ecb"):lower()
    local config = ciphers[mode]
    assert(config, "The AES supported modes are ECB, CBC, CTR, EAX, GCM, and CCM.")
    local bits = len * 8
    local cipher = config[bits]
    local context = ffi_new(cipher.context)
    cipher.setkey(context, key)
    local iv_size = config.iv_size
    if iv_size then
        iv = iv or ""
        if iv_size == huge then
            iv_size = #iv
        else
            if type(iv_size) == "table" then
                assert(#iv >= iv_size[1] and #iv <= iv_size[2], "The AES-" .. mode:upper() .. " supported initialization vector sizes are between " .. (iv_size[1] * 8) .. " and " .. (iv_size[2] * 8) .. " bits.")
                return setmetatable({
                    context = context,
                    cipher  = cipher,
                    iv      = iv,
                    ad      = ad
                }, ccm)
            else
                assert(#iv == iv_size, "The AES-" .. mode:upper() .. " supported initialization vector size is " .. (iv_size * 8) .. " bits.")
            end
        end
        if cipher.setiv then
            cipher.setiv(context, iv_size, iv)
        else
            return setmetatable({
                context = context,
                cipher  = cipher,
                iv      = iv }, aes)
        end
    end
    if ad and cipher.update then
        cipher.update(context, #ad, ad)
    end
    return setmetatable({
        context = context,
        cipher  = cipher }, aes)
end

function aes:encrypt(src, len)
    local cipher  = self.cipher
    local context = self.context
    if cipher.invert and self.inverted then
        cipher.invert(context, context)
        self.inverted = nil
    end
    len = len or #src
    if self.iv then
        local dln = len
        if cipher.invert then dln = ceil(dln / 16) * 16 end
        local dst = ffi_new(uint8t, dln)
        ffi_copy(dst, src, len)
        local ivl = #self.iv
        local iv = ffi_new(uint8t, ivl)
        ffi_copy(iv, self.iv, ivl)
        cipher.encrypt(context, cipher.cipher.encrypt, 16, iv, dln, dst, dst)
        return ffi_str(dst, dln)
    elseif cipher.digest then
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

function aes:decrypt(src, len)
    local cipher  = self.cipher
    local context = self.context
    if cipher.invert and not self.inverted then
        cipher.invert(context, context)
        self.inverted = true
    end
    len = len or #src
    if self.iv then
        local dln = cipher.invert and ceil(len / 16) * 16 or len
        local dst = ffi_new(uint8t, dln)
        local ivl = #self.iv
        local iv = ffi_new(uint8t, ivl)
        ffi_copy(iv, self.iv, ivl)
        cipher.decrypt(context, cipher.cipher.decrypt, 16, iv, dln, dst, src)
        return ffi_str(dst, len)
    elseif cipher.digest then
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

return aes
