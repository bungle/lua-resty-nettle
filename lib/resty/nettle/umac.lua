require "resty.nettle.types.aes"

local ffi        = require "ffi"
local ffi_new    = ffi.new
local ffi_typeof = ffi.typeof
local ffi_cdef   = ffi.cdef
local ffi_load   = ffi.load
local ffi_str    = ffi.string

ffi_cdef[[
typedef struct umac32_ctx {
  uint32_t l1_key[256];
  uint32_t l2_key[6];
  uint64_t l3_key1[8];
  uint32_t l3_key2[1];
  struct aes128_ctx pdf_key;
  uint64_t l2_state[3];
  uint8_t nonce[16];
  unsigned short nonce_length;
  unsigned short nonce_low;
  uint32_t pad_cache[4];
  unsigned index;
  uint64_t count;
  uint8_t block[1024];
} UMAC32_CTX;
typedef struct umac64_ctx {
  uint32_t l1_key[260];
  uint32_t l2_key[12];
  uint64_t l3_key1[16];
  uint32_t l3_key2[2];
  struct aes128_ctx pdf_key;
  uint64_t l2_state[6];
  uint8_t nonce[16];
  unsigned short nonce_length;
  unsigned short nonce_low;
  uint32_t pad_cache[4];
  unsigned index;
  uint64_t count;
  uint8_t block[1024];
} UMAC64_CTX;
typedef struct umac96_ctx {
  uint32_t l1_key[264];
  uint32_t l2_key[18];
  uint64_t l3_key1[24];
  uint32_t l3_key2[3];
  struct aes128_ctx pdf_key;
  uint64_t l2_state[9];
  uint8_t nonce[16];
  unsigned short nonce_length;
  unsigned index;
  uint64_t count;
  uint8_t block[1024];
} UMAC96_CTX;
typedef struct umac128_ctx {
  uint32_t l1_key[268];
  uint32_t l2_key[24];
  uint64_t l3_key1[32];
  uint32_t l3_key2[4];
  struct aes128_ctx pdf_key;
  uint64_t l2_state[12];
  uint8_t nonce[16];
  unsigned short nonce_length;
  unsigned index;
  uint64_t count;
  uint8_t block[1024];
} UMAC128_CTX;
void nettle_umac32_set_key(struct umac32_ctx *ctx, const uint8_t *key);
void nettle_umac64_set_key(struct umac64_ctx *ctx, const uint8_t *key);
void nettle_umac96_set_key(struct umac96_ctx *ctx, const uint8_t *key);
void nettle_umac128_set_key(struct umac128_ctx *ctx, const uint8_t *key);
void nettle_umac32_set_nonce(struct umac32_ctx *ctx, size_t nonce_length, const uint8_t *nonce);
void nettle_umac64_set_nonce(struct umac64_ctx *ctx, size_t nonce_length, const uint8_t *nonce);
void nettle_umac96_set_nonce(struct umac96_ctx *ctx, size_t nonce_length, const uint8_t *nonce);
void nettle_umac128_set_nonce(struct umac128_ctx *ctx, size_t nonce_length, const uint8_t *nonce);
void nettle_umac32_update(struct umac32_ctx *ctx, size_t length, const uint8_t *data);
void nettle_umac64_update(struct umac64_ctx *ctx, size_t length, const uint8_t *data);
void nettle_umac96_update(struct umac96_ctx *ctx, size_t length, const uint8_t *data);
void nettle_umac128_update(struct umac128_ctx *ctx, size_t length, const uint8_t *data);
void nettle_umac32_digest(struct umac32_ctx *ctx, size_t length, uint8_t *digest);
void nettle_umac64_digest(struct umac64_ctx *ctx, size_t length, uint8_t *digest);
void nettle_umac96_digest(struct umac96_ctx *ctx, size_t length, uint8_t *digest);
void nettle_umac128_digest(struct umac128_ctx *ctx, size_t length, uint8_t *digest);
]]

local nettle = ffi_load("libnettle")

local uint8t = ffi_typeof("uint8_t[?]")
local ctxu32 = ffi_typeof("UMAC32_CTX[1]")
local ctxu64 = ffi_typeof("UMAC64_CTX[1]")
local ctxu96 = ffi_typeof("UMAC96_CTX[1]")
local ctx128 = ffi_typeof("UMAC128_CTX[1]")
local bufu32 = ffi_new(uint8t, 4)
local bufu64 = ffi_new(uint8t, 8)
local bufu96 = ffi_new(uint8t, 12)
local buf128 = ffi_new(uint8t, 16)

local umac32 = {}
umac32.__index = umac32

function umac32.new(key, nonce)
    local self = setmetatable({ context = ffi_new(ctxu32) }, umac32)
    nettle.nettle_umac32_set_key(self.context, key)
    if nonce then
        nettle.nettle_umac32_set_nonce(self.context, #nonce, nonce)
    end
    return self
end

function umac32:update(data)
    return nettle.nettle_umac32_update(self.context, #data, data)
end

function umac32:digest()
    nettle.nettle_umac32_digest(self.context, 4, bufu32)
    return ffi_str(bufu32, 4)
end

local umac64 = {}
umac64.__index = umac64

function umac64.new(key, nonce)
    local self = setmetatable({ context = ffi_new(ctxu64) }, umac64)
    nettle.nettle_umac64_set_key(self.context, key)
    if nonce then
        nettle.nettle_umac64_set_nonce(self.context, #nonce, nonce)
    end
    return self
end

function umac64:update(data)
    return nettle.nettle_umac64_update(self.context, #data, data)
end

function umac64:digest()
    nettle.nettle_umac64_digest(self.context, 8, bufu64)
    return ffi_str(bufu64, 8)
end

local umac96 = {}
umac96.__index = umac96

function umac96.new(key, nonce)
    local self = setmetatable({ context = ffi_new(ctxu96) }, umac96)
    nettle.nettle_umac96_set_key(self.context, key)
    if nonce then
        nettle.nettle_umac96_set_nonce(self.context, #nonce, nonce)
    end
    return self
end

function umac96:update(data)
    return nettle.nettle_umac96_update(self.context, #data, data)
end

function umac96:digest()
    nettle.nettle_umac96_digest(self.context, 12, bufu96)
    return ffi_str(bufu96, 12)
end

local umac128 = {}
umac128.__index = umac128

function umac128.new(key, nonce)
    local self = setmetatable({ context = ffi_new(ctx128) }, umac128)
    nettle.nettle_umac128_set_key(self.context, key)
    if nonce then
        nettle.nettle_umac128_set_nonce(self.context, #nonce, nonce)
    end
    return self
end

function umac128:update(data)
    return nettle.nettle_umac128_update(self.context, #data, data)
end

function umac128:digest()
    nettle.nettle_umac128_digest(self.context, 16, buf128)
    return ffi_str(buf128, 16)
end

return {
    umac32  = umac32,
    umac64  = umac64,
    umac96  = umac96,
    umac128  = umac128
}