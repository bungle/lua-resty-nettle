local ffi = require "ffi"
local ffi_cdef = ffi.cdef
local ffi_typeof = ffi.typeof

ffi_cdef [[
void
nettle_base64_encode_init(struct base64_encode_ctx *ctx);

void
nettle_base64url_encode_init(struct base64_encode_ctx *ctx);

size_t
nettle_base64_encode_single(struct base64_encode_ctx *ctx,
                           char *dst,
                           uint8_t src);

size_t
nettle_base64_encode_update(struct base64_encode_ctx *ctx,
                            char *dst,
                            size_t length,
                            const uint8_t *src);

size_t
nettle_base64_encode_final(struct base64_encode_ctx *ctx,
                          char *dst);

void
nettle_base64_encode_raw(char *dst, size_t length, const uint8_t *src);

void
nettle_base64_encode_group(char *dst, uint32_t group);


void
nettle_base64_decode_init(struct base64_decode_ctx *ctx);

void
nettle_base64url_decode_init(struct base64_decode_ctx *ctx);

int
nettle_base64_decode_single(struct base64_decode_ctx *ctx,
                            uint8_t *dst,
                            char src);

int
nettle_base64_decode_update(struct base64_decode_ctx *ctx,
                            size_t *dst_length,
                            uint8_t *dst,
                            size_t src_length,
                            const char *src);

int
nettle_base64_decode_final(struct base64_decode_ctx *ctx);
]]

return {
  encode = ffi_typeof [[
struct base64_encode_ctx {
  const char *alphabet;
  unsigned short word;
  unsigned char bits;
}]],
  decode = ffi_typeof [[
struct base64_decode_ctx {
  const signed char *table;
  unsigned short word;
  unsigned char bits;
  unsigned char padding;
}]]
}
