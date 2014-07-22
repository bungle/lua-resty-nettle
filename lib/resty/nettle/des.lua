local ffi        = require "ffi"
local ffi_new    = ffi.new
local ffi_typeof = ffi.typeof
local ffi_cdef   = ffi.cdef
local ffi_str    = ffi.string
local ceil       = math.ceil
local nettle     = require "resty.nettle"

ffi_cdef[[
typedef struct des_ctx {
  uint32_t key[32];
} DES_CTX;
typedef struct des3_ctx {
  struct des_ctx des[3];
} DES3_CTX;
int  nettle_des_set_key(struct des_ctx *ctx, const uint8_t *key);
void nettle_des_encrypt(const struct des_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src);
void nettle_des_decrypt(const struct des_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src);
int  nettle_des_check_parity(size_t length, const uint8_t *key);
void nettle_des_fix_parity(size_t length, uint8_t *dst, const uint8_t *src);
int  nettle_des3_set_key(struct des3_ctx *ctx, const uint8_t *key);
void nettle_des3_encrypt(const struct des3_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src);
void nettle_des3_decrypt(const struct des3_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src);
]]

local uint8t = ffi_typeof("uint8_t[?]")

local des = {}
des.__index = des

local ciphers = {
    des = {
        context = ffi_typeof("DES_CTX[1]"),
        setkey  = nettle.nettle_des_set_key,
        encrypt = nettle.nettle_des_encrypt,
        decrypt = nettle.nettle_des_decrypt
    },
    des3 = {
        context = ffi_typeof("DES3_CTX[1]"),
        setkey  = nettle.nettle_des3_set_key,
        encrypt = nettle.nettle_des3_encrypt,
        decrypt = nettle.nettle_des3_decrypt
    }
}

function des.new(key)
    local len = #key
    assert(len == 8 or len == 24, "The DES supported key size is 64 bits, and DES3 supported key size is 192 bits.")
    local cipher
    if len == 8 then
       cipher = ciphers.des
    else
       cipher = ciphers.des3
    end
    local ct = ffi_new(cipher.context)
    local wk = cipher.setkey(ct, key)
    return setmetatable({ context = ct, cipher = cipher }, des), wk ~= 1
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

function des:encrypt(src)
    local len = ceil(#src / 8) * 8
    local dst = ffi_new(uint8t, len)
    self.cipher.encrypt(self.context, len, dst, src)
    return ffi_str(dst, len)
end

function des:decrypt(src)
    local len = ceil(#src / 8) * 8
    local dst = ffi_new(uint8t, len + 1)
    self.cipher.decrypt(self.context, len, dst, src)
    return ffi_str(dst)
end

return des
