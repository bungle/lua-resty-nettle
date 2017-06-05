local ffi      = require "ffi"
local ffi_load = ffi.load
local ipairs   = ipairs
local pcall    = pcall

local function L()
    local ok, lib = pcall(ffi_load, "gmp")
    if ok then return lib end
    for _, t in ipairs{ "so", "dylib", "dll" } do
        for i = 10, 3, -1 do
            ok, lib = pcall(ffi_load, "gmp." .. i)
            if ok then return lib end
            ok, lib = pcall(ffi_load, "gmp." .. t .. "." .. i)
            if ok then return lib end
            ok, lib = pcall(ffi_load, "libgmp." .. t .. "." .. i)
            if ok then return lib end
        end
    end
    return nil, "unable to load gmp"
end

return L()
