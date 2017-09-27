local ffi      = require "ffi"
local ffi_load = ffi.load
local ipairs   = ipairs
local pcall    = pcall
local lib_path = _GMP_LIB_PATH

if lib_path then
    local sub = string.sub
    local sep = sub(package.config, 1, 1) or "/"
    if sub(lib_path, -1) ~= sep then
        lib_path = lib_path .. sep
    end
end

local function L()
    local ok, lib

    if lib_path then
        for _, t in ipairs{ "so", "dylib", "dll" } do
            ok, lib = pcall(ffi_load, lib_path .. "libgmp." .. t)
            if ok and lib then return lib end
            ok, lib = pcall(ffi_load, lib_path .. "gmp." .. t)
            if ok and lib then return lib end
            for i = 10, 3, -1 do
                ok, lib = pcall(ffi_load, lib_path .. "libgmp." .. t .. "." .. i)
                if ok and lib then return lib end
                ok, lib = pcall(ffi_load, lib_path .. "gmp." .. t .. "." .. i)
                if ok and lib then return lib end
                ok, lib = pcall(ffi_load, lib_path .. "gmp." .. i)
                if ok and lib then return lib end
            end
        end
    end

    ok, lib = pcall(ffi_load, "gmp")
    if ok and lib then return lib end

    for _, t in ipairs{ "so", "dylib", "dll" } do
        ok, lib = pcall(ffi_load, "gmp." .. t)
        if ok and lib then return lib end
        for i = 10, 3, -1 do
            ok, lib = pcall(ffi_load, "gmp." .. i)
            if ok and lib then return lib end
            ok, lib = pcall(ffi_load, "gmp." .. t .. "." .. i)
            if ok and lib then return lib end
            ok, lib = pcall(ffi_load, "libgmp." .. t .. "." .. i)
            if ok and lib then return lib end
        end
    end

    return nil, "unable to load gmp"
end

return L()
