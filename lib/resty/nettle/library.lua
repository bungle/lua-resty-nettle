local ffi      = require "ffi"
local ffi_load = ffi.load
local ffi_cdef = ffi.cdef
local pcall    = pcall

ffi_cdef[[
union nettle_block16 { uint8_t b[16]; unsigned long w[16 / sizeof(unsigned long)]; };
typedef void *nettle_realloc_func(void *ctx, void *p, size_t length);
typedef void nettle_cipher_func(const void *ctx, size_t length, uint8_t *dst, const uint8_t *src);
typedef void nettle_random_func(void *ctx, size_t length, uint8_t *dst);
typedef void nettle_progress_func(void *ctx, int c);
]]

local function L()
    local ok, lib = pcall(ffi_load, "nettle")
    if ok then return lib end
    ok, lib = pcall(ffi_load, "nettle.6")
    if ok then return lib end
    ok, lib = pcall(ffi_load, "nettle.so.6")
    if ok then return lib end
    return ffi_load "libnettle.so.6"
end

return L()
