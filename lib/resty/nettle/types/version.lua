local ffi = require "ffi"
local ffi_cdef = ffi.cdef

ffi_cdef [[
int
nettle_version_major (void);

int
nettle_version_minor (void);
]]
