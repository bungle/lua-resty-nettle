require "resty.nettle.types.aes"

local lib          = require "resty.nettle.library"
local ffi          = require "ffi"
local ffi_new      = ffi.new
local ffi_typeof   = ffi.typeof
local ffi_cdef     = ffi.cdef
local ffi_str      = ffi.string
local assert       = assert
local setmetatable = setmetatable

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

local uint8t = ffi_typeof "uint8_t[?]"
local ctxu32 = ffi_typeof "UMAC32_CTX[1]"
local ctxu64 = ffi_typeof "UMAC64_CTX[1]"
local ctxu96 = ffi_typeof "UMAC96_CTX[1]"
local ctx128 = ffi_typeof "UMAC128_CTX[1]"
local bufu32 = ffi_new(uint8t, 4)
local bufu64 = ffi_new(uint8t, 8)
local bufu96 = ffi_new(uint8t, 12)
local buf128 = ffi_new(uint8t, 16)

local umacs = {
    [32]         = {
        length   = 4,
        context  = ctxu32,
        buffer   = bufu32,
        setkey   = lib.nettle_umac32_set_key,
        setnonce = lib.nettle_umac32_set_nonce,
        update   = lib.nettle_umac32_update,
        digest   = lib.nettle_umac32_digest
    },
    [64]         = {
        length   = 8,
        context  = ctxu64,
        buffer   = bufu64,
        setkey   = lib.nettle_umac64_set_key,
        setnonce = lib.nettle_umac64_set_nonce,
        update   = lib.nettle_umac64_update,
        digest   = lib.nettle_umac64_digest
    },
    [96]         = {
        length   = 12,
        context  = ctxu96,
        buffer   = bufu96,
        setkey   = lib.nettle_umac96_set_key,
        setnonce = lib.nettle_umac96_set_nonce,
        update   = lib.nettle_umac96_update,
        digest   = lib.nettle_umac96_digest
    },
    [128]        = {
        length   = 16,
        context  = ctx128,
        buffer   = buf128,
        setkey   = lib.nettle_umac128_set_key,
        setnonce = lib.nettle_umac128_set_nonce,
        update   = lib.nettle_umac128_update,
        digest   = lib.nettle_umac128_digest
    }
}

local umac = {}
umac.__index = umac

function umac:update(data, len)
    return self.umac.update(self.context, len or #data, data)
end

function umac:digest()
    local umac = self.umac
    umac.digest(self.context, umac.length, umac.buffer)
    return ffi_str(umac.buffer, umac.length)
end

local function factory(mac)
    return setmetatable({ new = function(key, nonce)
        local ctx = ffi_new(mac.context)
        mac.setkey(ctx, key)
        if nonce then
            mac.setnonce(ctx, #nonce, nonce)
        end
        return setmetatable({ context = ctx, umac = mac }, umac)
    end }, {
        __call = function(_, key, nonce, data, len)
            local ctx = ffi_new(mac.context)
            mac.setkey(ctx, key)
            if nonce then
                mac.setnonce(ctx, #nonce, nonce)
            end
            mac.update(ctx, len or #data, data)
            mac.digest(ctx, mac.length, mac.buffer)
            return ffi_str(mac.buffer, mac.length)
        end
    })
end

return setmetatable({
    umac32  = factory(umacs[32]),
    umac64  = factory(umacs[64]),
    umac96  = factory(umacs[96]),
    umac128 = factory(umacs[128])
}, { __call = function(_, bits, key, nonce, data, len)
    local mac = umacs[bits]
    assert(mac, "The supported UMAC algorithm output sizes are 32, 64, 96, and 128 bits")
    local ctx = ffi_new(mac.context)
    mac.setkey(ctx, key)
    if nonce then
        mac.setnonce(ctx, #nonce, nonce)
    end
    mac.update(ctx, len or #data, data)
    mac.digest(ctx, mac.length, mac.buffer)
    return ffi_str(mac.buffer, mac.length)
end })
