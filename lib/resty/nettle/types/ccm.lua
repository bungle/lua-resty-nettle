require "resty.nettle"
require "resty.nettle.types.aes"

local ffi        = require "ffi"
local ffi_cdef   = ffi.cdef

ffi_cdef[[
typedef struct ccm_ctx {
  union nettle_block16 ctr;
  union nettle_block16 tag;
  unsigned int blength;
} CCM_CTX;
typedef struct ccm_aes128_ctx {
    struct ccm_ctx      ccm;
    struct aes128_ctx   cipher;
} CCM_AES128_CTX;
typedef struct ccm_aes192_ctx {
    struct ccm_ctx      ccm;
    struct aes192_ctx   cipher;
} CCM_AES192_CTX;
typedef struct ccm_aes256_ctx {
    struct ccm_ctx      ccm;
    struct aes256_ctx   cipher;
} CCM_AES256_CTX;
]]