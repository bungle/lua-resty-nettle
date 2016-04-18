require "resty.nettle.types.des"

local ffi          = require "ffi"
local ffi_new      = ffi.new
local ffi_typeof   = ffi.typeof
local ffi_copy     = ffi.copy
local ffi_cdef     = ffi.cdef
local ffi_str      = ffi.string
local ceil         = math.ceil
local assert       = assert
local setmetatable = setmetatable
local nettle       = require "resty.nettle"

ffi_cdef[[
int  nettle_des_set_key(struct des_ctx *ctx, const uint8_t *key);
void nettle_des_encrypt(const struct des_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src);
void nettle_des_decrypt(const struct des_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src);
int  nettle_des_check_parity(size_t length, const uint8_t *key);
void nettle_des_fix_parity(size_t length, uint8_t *dst, const uint8_t *src);
int  nettle_des3_set_key(struct des3_ctx *ctx, const uint8_t *key);
void nettle_des3_encrypt(const struct des3_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src);
void nettle_des3_decrypt(const struct des3_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src);
]]

local uint8t = ffi_typeof "uint8_t[?]"

local des = {}
des.__index = des

local ciphers = {
    des = {
        ecb = {
            context = ffi_typeof "DES_CTX[1]",
            setkey  = nettle.nettle_des_set_key,
            encrypt = nettle.nettle_des_encrypt,
            decrypt = nettle.nettle_des_decrypt
        },
        cbc = {
            iv_size = 8,
            context = ffi_typeof "DES_CTX[1]",
            setkey  = nettle.nettle_des_set_key,
            encrypt = nettle.nettle_cbc_encrypt,
            decrypt = nettle.nettle_cbc_decrypt,
            cipher  = {
                encrypt = nettle.nettle_des_encrypt,
                decrypt = nettle.nettle_des_decrypt
            }
        },
        ctr = {
            iv_size = 8,
            context = ffi_typeof "DES_CTX[1]",
            setkey  = nettle.nettle_des_set_key,
            encrypt = nettle.nettle_ctr_crypt,
            decrypt = nettle.nettle_ctr_crypt,
            cipher  = {
                encrypt = nettle.nettle_des_encrypt,
                decrypt = nettle.nettle_des_encrypt
            }
        }
    },
    des3 = {
        ecb = {
            context = ffi_typeof "DES3_CTX[1]",
            setkey  = nettle.nettle_des3_set_key,
            encrypt = nettle.nettle_des3_encrypt,
            decrypt = nettle.nettle_des3_decrypt
        },
        cbc = {
            iv_size = 8,
            context = ffi_typeof "DES3_CTX[1]",
            setkey  = nettle.nettle_des3_set_key,
            encrypt = nettle.nettle_cbc_encrypt,
            decrypt = nettle.nettle_cbc_decrypt,
            cipher  = {
                encrypt = nettle.nettle_des3_encrypt,
                decrypt = nettle.nettle_des3_decrypt
            }
        },
        ctr = {
            iv_size = 8,
            context = ffi_typeof "DES3_CTX[1]",
            setkey  = nettle.nettle_des3_set_key,
            encrypt = nettle.nettle_ctr_crypt,
            decrypt = nettle.nettle_ctr_crypt,
            cipher  = {
                encrypt = nettle.nettle_des3_encrypt,
                decrypt = nettle.nettle_des3_encrypt
            }
        }
    }
}

function des.new(key, mode, iv)
    local len = #key
    assert(len == 8 or len == 24, "The DES supported key size is 64 bits, and DES3 supported key size is 192 bits.")
    local cipher
    if len == 8 then
       cipher = ciphers.des
    else
       cipher = ciphers.des3
    end
    mode = (mode or "ecb"):lower()
    cipher = cipher[mode]
    assert(cipher, "The DES/DES3 supported modes are currently ECB, CBC, and CTR.")
    local iv_size = cipher.iv_size
    if iv_size then
        assert(#iv == iv_size, "The DES-/DES3-" .. mode:upper() .. " supported initialization vector size is " .. (iv_size * 8) .. " bits.")
    end
    local ct = ffi_new(cipher.context)
    local wk = cipher.setkey(ct, key)
    return setmetatable({ context = ct, cipher = cipher, iv = iv }, des), wk ~= 1
end

function des.check_parity(key)
    local len = #key
    assert(len == 8 or len == 24, "The DES supported key size is 64 bits, and DES3 supported key size is 192 bits.")
    return nettle.nettle_des_check_parity(len, key) == 1
end

function des.fix_parity(src)
    local len = #src
    assert(len == 8 or len == 24, "The DES supported key size is 64 bits, and DES3 supported key size is 192 bits.")
    local dst = ffi_new(uint8t, len)
    nettle.nettle_des_fix_parity(len, dst, src)
    return ffi_str(dst, len)
end

function des:encrypt(src, len)
    len = len or #src
    local cipher  = self.cipher
    local context = self.context
    local dln = ceil(len / 8) * 8
    local dst = ffi_new(uint8t, dln)
    ffi_copy(dst, src, len)
    if self.iv then
        local iv = ffi_new(uint8t, 8)
        ffi_copy(iv, self.iv, 8)
        cipher.encrypt(context, cipher.cipher.encrypt, 8, iv, dln, dst, dst)
    else
        cipher.encrypt(context, dln, dst, dst)
    end
    return ffi_str(dst, dln)
end

function des:decrypt(src, len)
    local cipher  = self.cipher
    local context = self.context
    len = len or #src
    local dln = ceil(len / 8) * 8
    local dst = ffi_new(uint8t, dln)
    if self.iv then
        local iv = ffi_new(uint8t, 8)
        ffi_copy(iv, self.iv, 8)
        cipher.decrypt(context, cipher.cipher.decrypt, 8, iv, dln, dst, src)
    else
        cipher.decrypt(context, dln, dst, src)
    end
    return ffi_str(dst, len)
end

return des
