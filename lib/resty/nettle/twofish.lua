require "resty.nettle.types.cbc"
require "resty.nettle.types.ctr"
require "resty.nettle.types.gcm"

local lib          = require "resty.nettle.library"
local ffi          = require "ffi"
local ffi_new      = ffi.new
local ffi_typeof   = ffi.typeof
local ffi_cdef     = ffi.cdef
local ffi_copy     = ffi.copy
local ffi_str      = ffi.string
local ceil         = math.ceil
local setmetatable = setmetatable

ffi_cdef[[
typedef struct twofish_ctx {
  uint32_t keys[40];
  uint32_t s_box[4][256];
} NETTLE_TWOFISH_CTX;
void nettle_twofish_set_key(struct twofish_ctx *ctx, size_t length, const uint8_t *key);
void nettle_twofish128_set_key(struct twofish_ctx *context, const uint8_t *key);
void nettle_twofish192_set_key(struct twofish_ctx *context, const uint8_t *key);
void nettle_twofish256_set_key(struct twofish_ctx *context, const uint8_t *key);
void nettle_twofish_encrypt(const struct twofish_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src);
void nettle_twofish_decrypt(const struct twofish_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src);
]]

local uint8t = ffi_typeof "uint8_t[?]"

local ciphers = {
    ecb = {
        [128] = {
            setkey  = lib.nettle_twofish128_set_key,
            encrypt = lib.nettle_twofish_encrypt,
            decrypt = lib.nettle_twofish_decrypt
        },
        [192] = {
            setkey  = lib.nettle_twofish192_set_key,
            encrypt = lib.nettle_twofish_encrypt,
            decrypt = lib.nettle_twofish_decrypt
        },
        [256] = {
            setkey  = lib.nettle_twofish256_set_key,
            encrypt = lib.nettle_twofish_encrypt,
            decrypt = lib.nettle_twofish_decrypt
        }
    },
    cbc = {
        iv_size  = 16,
        [128] = {
            setkey  = lib.nettle_twofish128_set_key,
            encrypt = lib.nettle_cbc_encrypt,
            decrypt = lib.nettle_cbc_decrypt,
            padding = true,
            cipher  = {
                encrypt = lib.nettle_twofish_encrypt,
                decrypt = lib.nettle_twofish_decrypt
            }
        },
        [192] = {
            setkey  = lib.nettle_twofish192_set_key,
            encrypt = lib.nettle_cbc_encrypt,
            decrypt = lib.nettle_cbc_decrypt,
            padding = true,
            cipher  = {
                encrypt = lib.nettle_twofish_encrypt,
                decrypt = lib.nettle_twofish_decrypt
            }
        },
        [256] = {
            setkey  = lib.nettle_twofish256_set_key,
            encrypt = lib.nettle_cbc_encrypt,
            decrypt = lib.nettle_cbc_decrypt,
            padding = true,
            cipher  = {
                encrypt = lib.nettle_twofish_encrypt,
                decrypt = lib.nettle_twofish_decrypt
            }
        }
    },
    ctr = {
        iv_size  = 16,
        [128] = {
            setkey  = lib.nettle_twofish128_set_key,
            encrypt  = lib.nettle_ctr_crypt,
            decrypt  = lib.nettle_ctr_crypt,
            cipher  = {
                encrypt = lib.nettle_twofish_encrypt,
                decrypt = lib.nettle_twofish_encrypt
            }
        },
        [192] = {
            setkey  = lib.nettle_twofish192_set_key,
            encrypt  = lib.nettle_ctr_crypt,
            decrypt  = lib.nettle_ctr_crypt,
            cipher  = {
                encrypt = lib.nettle_twofish_encrypt,
                decrypt = lib.nettle_twofish_encrypt
            }
        },
        [256] = {
            setkey  = lib.nettle_twofish256_set_key,
            encrypt = lib.nettle_ctr_crypt,
            decrypt = lib.nettle_ctr_crypt,
            cipher  = {
                encrypt = lib.nettle_twofish_encrypt,
                decrypt = lib.nettle_twofish_encrypt
            }
        }
    },
    gcm = {
        iv_size  = 12,
        [128] = {
            setkey  = lib.nettle_gcm_set_key,
            setiv   = lib.nettle_gcm_set_iv,
            update  = lib.nettle_gcm_update,
            encrypt = lib.nettle_gcm_encrypt,
            decrypt = lib.nettle_gcm_decrypt,
            digest  = lib.nettle_gcm_digest,
            key     = ffi_typeof "NETTLE_GCM_KEY[1]",
            context = ffi_typeof "NETTLE_GCM_CTX[1]",
            cipher  = {
                setkey  = lib.nettle_twofish128_set_key,
                encrypt = lib.nettle_twofish_encrypt,
                decrypt = lib.nettle_twofish_decrypt
            }
        },
        [192] = {
            setkey  = lib.nettle_gcm_set_key,
            setiv   = lib.nettle_gcm_set_iv,
            update  = lib.nettle_gcm_update,
            encrypt = lib.nettle_gcm_encrypt,
            decrypt = lib.nettle_gcm_decrypt,
            digest  = lib.nettle_gcm_digest,
            key     = ffi_typeof "NETTLE_GCM_KEY[1]",
            context = ffi_typeof "NETTLE_GCM_CTX[1]",
            cipher  = {
                setkey  = lib.nettle_twofish192_set_key,
                encrypt = lib.nettle_twofish_encrypt,
                decrypt = lib.nettle_twofish_decrypt
            }
        },
        [256] = {
            setkey  = lib.nettle_gcm_set_key,
            setiv   = lib.nettle_gcm_set_iv,
            update  = lib.nettle_gcm_update,
            encrypt = lib.nettle_gcm_encrypt,
            decrypt = lib.nettle_gcm_decrypt,
            digest  = lib.nettle_gcm_digest,
            key     = ffi_typeof "NETTLE_GCM_KEY[1]",
            context = ffi_typeof "NETTLE_GCM_CTX[1]",
            cipher  = {
                setkey  = lib.nettle_twofish256_set_key,
                encrypt = lib.nettle_twofish_encrypt,
                decrypt = lib.nettle_twofish_decrypt
            }
        }
    }
}

local context = ffi_typeof "NETTLE_TWOFISH_CTX[1]"
local twofish = {}
twofish.__index = twofish

function twofish.new(key, mode, iv, ad)
    local len = #key
    if len ~= 16 and len ~= 24 and len ~= 32 then
        return nil, "the TWOFISH supported key sizes are 128, 192, and 256 bits"
    end
    mode = (mode or "ecb"):lower()
    local config = ciphers[mode]
    if not config then
        return nil, "the TWOFISH supported modes are ECB, CBC, and CTR"
    end
    local bits = len * 8
    local cipher = config[bits]
    local context = ffi_new(context)
    cipher.setkey(context, key)
    local iv_size = config.iv_size
    if iv_size then
        iv = iv or ""
        if #iv ~= iv_size then
            return "the TWOFISH-" .. mode:upper() .. " supported initialization vector size is " .. (iv_size * 8) .. " bits"
        end
    end
    return setmetatable({
        context = context,
        cipher  = cipher,
        iv      = iv }, twofish)
end

function twofish:encrypt(src, len)
    local cipher  = self.cipher
    local context = self.context
    len = len or #src
    if self.iv then
        local dln = len
        if cipher.padding then dln = ceil(dln / 16) * 16 end
        local dst = ffi_new(uint8t, dln)
        ffi_copy(dst, src, len)
        local ivl = #self.iv
        local iv = ffi_new(uint8t, ivl)
        ffi_copy(iv, self.iv, ivl)
        cipher.encrypt(context, cipher.cipher.encrypt, 16, iv, dln, dst, dst)
        return ffi_str(dst, dln)
    end
    local dln = ceil(len / 16) * 16
    local dst = ffi_new(uint8t, dln)
    ffi_copy(dst, src, len)
    cipher.encrypt(context, dln, dst, dst)
    return ffi_str(dst, dln)
end

function twofish:decrypt(src, len)
    local cipher  = self.cipher
    local context = self.context
    len = len or #src
    if self.iv then
        local dst = ffi_new(uint8t, len)
        local ivl = #self.iv
        local iv = ffi_new(uint8t, ivl)
        ffi_copy(iv, self.iv, ivl)
        cipher.decrypt(context, cipher.cipher.decrypt, 16, iv, len, dst, src)
        return ffi_str(dst, len)

    end
    local dln = ceil(len / 16) * 16
    local dst = ffi_new(uint8t, dln)
    cipher.decrypt(self.context, dln, dst, src)
    return ffi_str(dst, len)
end
return twofish
