require "resty.nettle.types.nettle-types"

local ffi = require "ffi"
local ffi_load = ffi.load
local ipairs = ipairs
local assert = assert
local pcall = pcall
local lib_path = _NETTLE_LIB_PATH -- luacheck: ignore

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
    for _, t in ipairs { "so", "dylib", "dll" } do
      ok, lib = pcall(ffi_load, lib_path .. "libnettle." .. t)
      if ok and lib then return lib end
      ok, lib = pcall(ffi_load, lib_path .. "nettle." .. t)
      if ok and lib then return lib end
      for i = 7, 6, -1 do
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
  for _, t in ipairs { "so", "dylib", "dll" } do
    ok, lib = pcall(ffi_load, "nettle." .. t)
    if ok and lib then return lib end
    for i = 7, 6, -1 do
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

return (assert(L()))
