require "resty.nettle.types.aes"

local ffi = require "ffi"
local ffi_cdef = ffi.cdef
local ffi_typeof = ffi.typeof

ffi_cdef [[
void
nettle_umac32_set_key(struct umac32_ctx *ctx, const uint8_t *key);

void
nettle_umac64_set_key(struct umac64_ctx *ctx, const uint8_t *key);

void
nettle_umac96_set_key(struct umac96_ctx *ctx, const uint8_t *key);

void
nettle_umac128_set_key(struct umac128_ctx *ctx, const uint8_t *key);


void
nettle_umac32_set_nonce(struct umac32_ctx *ctx,
                        size_t nonce_length, const uint8_t *nonce);

void
nettle_umac64_set_nonce(struct umac64_ctx *ctx,
                        size_t nonce_length, const uint8_t *nonce);

void
nettle_umac96_set_nonce(struct umac96_ctx *ctx,
                        size_t nonce_length, const uint8_t *nonce);

void
nettle_umac128_set_nonce(struct umac128_ctx *ctx,
                         size_t nonce_length, const uint8_t *nonce);


void
nettle_umac32_update(struct umac32_ctx *ctx,
                     size_t length, const uint8_t *data);

void
nettle_umac64_update(struct umac64_ctx *ctx,
                     size_t length, const uint8_t *data);

void
nettle_umac96_update(struct umac96_ctx *ctx,
                     size_t length, const uint8_t *data);

void
nettle_umac128_update(struct umac128_ctx *ctx,
                      size_t length, const uint8_t *data);


void
nettle_umac32_digest(struct umac32_ctx *ctx,
                     size_t length, uint8_t *digest);

void
nettle_umac64_digest(struct umac64_ctx *ctx,
                     size_t length, uint8_t *digest);

void
nettle_umac96_digest(struct umac96_ctx *ctx,
                     size_t length, uint8_t *digest);

void
nettle_umac128_digest(struct umac128_ctx *ctx,
                      size_t length, uint8_t *digest);
]]

return {
  umac32 = ffi_typeof [[
struct umac32_ctx {
  uint32_t l1_key[1024/4 + 4*((1)-1)];
  uint32_t l2_key[6*(1)];
  uint64_t l3_key1[8*(1)];
  uint32_t l3_key2[(1)];
  struct aes128_ctx pdf_key;
  uint64_t l2_state[3*(1)];
  uint8_t nonce[16];
  unsigned short nonce_length;
  unsigned short nonce_low;
  uint32_t pad_cache[16 / 4];
  unsigned index;
  uint64_t count;
  uint8_t block[1024];
}]],
  umac64 = ffi_typeof [[
struct umac64_ctx {
  uint32_t l1_key[1024/4 + 4*((2)-1)];
  uint32_t l2_key[6*(2)];
  uint64_t l3_key1[8*(2)];
  uint32_t l3_key2[(2)];
  struct aes128_ctx pdf_key;
  uint64_t l2_state[3*(2)];
  uint8_t nonce[16];
  unsigned short nonce_length;
  unsigned short nonce_low;
  uint32_t pad_cache[16/4];
  unsigned index;
  uint64_t count;
  uint8_t block[1024];
}]],
  umac96 = ffi_typeof [[
struct umac96_ctx {
  uint32_t l1_key[1024/4 + 4*((3)-1)];
  uint32_t l2_key[6*(3)];
  uint64_t l3_key1[8*(3)];
  uint32_t l3_key2[(3)];
  struct aes128_ctx pdf_key;
  uint64_t l2_state[3*(3)];
  uint8_t nonce[16];
  unsigned short nonce_length;
  unsigned index;
  uint64_t count;
  uint8_t block[1024];
}]],
  umac128 = ffi_typeof [[
struct umac128_ctx {
  uint32_t l1_key[1024/4 + 4*((4)-1)];
  uint32_t l2_key[6*(4)];
  uint64_t l3_key1[8*(4)];
  uint32_t l3_key2[(4)];
  struct aes128_ctx pdf_key;
  uint64_t l2_state[3*(4)];
  uint8_t nonce[16];
  unsigned short nonce_length;
  unsigned index;
  uint64_t count;
  uint8_t block[1024];
}]],
}
