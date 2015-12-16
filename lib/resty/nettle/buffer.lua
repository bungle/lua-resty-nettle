require "resty.nettle.types.buffer"

local ffi        = require "ffi"
local ffi_gc     = ffi.gc
local ffi_new    = ffi.new
local ffi_cdef   = ffi.cdef
local ffi_typeof = ffi.typeof
local nettle     = require "resty.nettle"

ffi_cdef[[
void      nettle_buffer_init(struct nettle_buffer *buffer);
void      nettle_buffer_init_realloc(struct nettle_buffer *buffer, void *realloc_ctx, nettle_realloc_func *realloc);
void      nettle_buffer_init_size(struct nettle_buffer *buffer, size_t length, uint8_t *space);
void      nettle_buffer_clear(struct nettle_buffer *buffer);
void      nettle_buffer_reset(struct nettle_buffer *buffer);
int       nettle_buffer_grow(struct nettle_buffer *buffer, size_t length);
int       nettle_buffer_write(struct nettle_buffer *buffer, size_t length, const uint8_t *data);
uint8_t * nettle_buffer_space(struct nettle_buffer *buffer, size_t length);
int       nettle_buffer_copy(struct nettle_buffer *dst, const struct nettle_buffer *src);
]]

local buf = ffi_typeof "NETTLE_BUFFER"
local buffer = {}

function buffer.new()
    local b = ffi_gc(ffi_new(buf), nettle.nettle_buffer_clear)
    nettle.nettle_buffer_init(b)
    return b
end

return buffer
