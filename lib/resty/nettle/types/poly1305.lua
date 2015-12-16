require "resty.nettle.types.aes"

local ffi      = require "ffi"
local ffi_cdef = ffi.cdef

ffi_cdef[[
typedef struct poly1305_ctx {
  union {
    uint32_t r32[6];
    uint64_t r64[3];
  } r;
  uint32_t s32[3];
  uint32_t hh;
  union {
    uint32_t h32[4];
    uint64_t h64[2];
  } h;
} POLY1305_CTX;
typedef struct poly1305_aes_ctx {
  struct poly1305_ctx pctx;
  uint8_t block[16];
  unsigned index;
  uint8_t nonce[16];
  struct aes128_ctx aes;
} POLY1305_AES_CTX;
]]