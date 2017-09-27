local ffi      = require "ffi"
local ffi_load = ffi.load
local ffi_cdef = ffi.cdef
local ipairs   = ipairs
local pcall    = pcall
local lib_path = _NETTLE_LIB_PATH

if lib_path then
    local sub = string.sub
    local sep = sub(package.config, 1, 1) or "/"
    if sub(lib_path, -1) ~= sep then
        lib_path = lib_path .. sep
    end
end


ffi_cdef[[
union nettle_block16 { uint8_t b[16]; unsigned long w[16 / sizeof(unsigned long)]; };
typedef void *nettle_realloc_func(void *ctx, void *p, size_t length);
typedef void nettle_cipher_func(const void *ctx, size_t length, uint8_t *dst, const uint8_t *src);
typedef void nettle_random_func(void *ctx, size_t length, uint8_t *dst);
typedef void nettle_progress_func(void *ctx, int c);
]]

local function L()
    local ok, lib

    if lib_path then
        for _, t in ipairs{ "so", "dylib", "dll" } do
            ok, lib = pcall(ffi_load, lib_path .. "libnettle." .. t)
            if ok and lib then return lib end
            ok, lib = pcall(ffi_load, lib_path .. "nettle." .. t)
            if ok and lib then return lib end
            for i = 6, 4, -1 do
                ok, lib = pcall(ffi_load, lib_path .. "libnettle." .. t .. "." .. i)
                if ok and lib then return lib end
                ok, lib = pcall(ffi_load, lib_path .. "nettle." .. t .. "." .. i)
                if ok and lib then return lib end
                ok, lib = pcall(ffi_load, lib_path .. "nettle." .. i)
                if ok and lib then return lib end
            end
        end
    end

    ok, lib = pcall(ffi_load, "nettle")
    if ok and lib then return lib end
    for _, t in ipairs{ "so", "dylib", "dll" } do
        ok, lib = pcall(ffi_load, "nettle." .. t)
        if ok and lib then return lib end
        if ok and lib then return lib end
        for i = 6, 4, -1 do
            ok, lib = pcall(ffi_load, "nettle." .. i)
            if ok and lib then return lib end
            ok, lib = pcall(ffi_load, "nettle." .. t .. "." .. i)
            if ok and lib then return lib end
            ok, lib = pcall(ffi_load, "libnettle." .. t .. "." .. i)
            if ok and lib then return lib end
        end
    end
    return nil, "unable to load nettle"
end

return L()
