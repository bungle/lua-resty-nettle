local ffi      = require "ffi"
local ffi_load = ffi.load
local pcall    = pcall

local function L()
    local ok, lib = pcall(ffi_load, "gmp")
    if ok then return lib end
    ok, lib = pcall(ffi_load, "gmp.10")
    if ok then return lib end
    ok, lib = pcall(ffi_load, "gmp.so.10")
    if ok then return lib end
    return ffi_load "libgmp.so.10"
end

return L()
