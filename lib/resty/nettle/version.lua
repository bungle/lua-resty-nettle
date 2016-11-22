local lib          = require "resty.nettle.library"
local ffi          = require "ffi"
local ffi_cdef     = ffi.cdef
local concat       = table.concat
local setmetatable = setmetatable
ffi_cdef[[
int nettle_version_major(void);
int nettle_version_minor(void);
]]
local minor = lib.nettle_version_minor()
local major = lib.nettle_version_major()
local version = concat({ major, minor}, ".")
return setmetatable({ major = major, minor = minor }, {
    __tostring = function() return version end
})