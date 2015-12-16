require "resty.nettle.types.cbc"
require "resty.nettle.types.ctr"
require "resty.nettle.types.eax"
require "resty.nettle.types.gcm"
require "resty.nettle.types.ccm"

local ffi      = require "ffi"
local ffi_cdef = ffi.cdef

ffi_cdef[[
typedef struct aes128_ctx {
  uint32_t keys[44];
} AES128_CTX;
typedef struct aes192_ctx {
  uint32_t keys[52];
} AES192_CTX;
typedef struct aes256_ctx {
  uint32_t keys[60];
} AES256_CTX;
typedef struct eax_aes128_ctx {
  struct eax_key key;
  struct eax_ctx eax;
  struct aes128_ctx cipher;
} EAX_AES128_CTX;
typedef struct gcm_aes128_ctx {
  struct gcm_key key;
  struct gcm_ctx gcm;
  struct aes128_ctx cipher;
} GCM_AES128_CTX;
typedef struct gcm_aes192_ctx {
  struct gcm_key key;
  struct gcm_ctx gcm;
  struct aes192_ctx cipher;
} GCM_AES192_CTX;
typedef struct gcm_aes256_ctx {
  struct gcm_key key;
  struct gcm_ctx gcm;
  struct aes256_ctx cipher;
} GCM_AES256_CTX;
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