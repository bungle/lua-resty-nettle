local ffi      = require "ffi"
local ffi_load = ffi.load
local ipairs   = ipairs
local pcall    = pcall

local function L()
    local ok, lib = pcall(ffi_load, "hogweed")
    if ok and lib then return lib end
    for _, t in ipairs{ "so", "dylib", "dll" } do
        ok, lib = pcall(ffi_load, "hogweed." .. t)
        if ok and lib then return lib end
        for i = 4, 2, -1 do
            ok, lib = pcall(ffi_load, "hogweed." .. i)
            if ok and lib then return lib end
            ok, lib = pcall(ffi_load, "hogweed." .. t .. "." .. i)
            if ok and lib then return lib end
            ok, lib = pcall(ffi_load, "libhogweed." .. t .. "." .. i)
            if ok and lib then return lib end
        end
    end
    return nil, "unable to load hogweed"
end

return L()
