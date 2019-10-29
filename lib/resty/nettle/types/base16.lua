local ffi = require "ffi"
local ffi_cdef = ffi.cdef
local ffi_typeof = ffi.typeof

ffi_cdef [[
void
nettle_base16_encode_single(char *dst,
                            uint8_t src);

void
nettle_base16_encode_update(char *dst,
                            size_t length,
                            const uint8_t *src);

void
nettle_base16_decode_init(struct base16_decode_ctx *ctx);

int
nettle_base16_decode_single(struct base16_decode_ctx *ctx,
                            uint8_t *dst,
                            char src);

int
nettle_base16_decode_update(struct base16_decode_ctx *ctx,
                            size_t *dst_length,
                            uint8_t *dst,
                            size_t src_length,
                            const char *src);

int
nettle_base16_decode_final(struct base16_decode_ctx *ctx);
]]

return ffi_typeof [[
struct base16_decode_ctx {
  unsigned char word;
  unsigned char bits;
}]]
