require "resty.nettle.types.version"

local lib = require "resty.nettle.library"
local concat = table.concat
local setmetatable = setmetatable

local minor = lib.nettle_version_minor()
local major = lib.nettle_version_major()
local version = concat({ major, minor }, ".")
return setmetatable({ major = major, minor = minor }, {
  __tostring = function() return version end
})
