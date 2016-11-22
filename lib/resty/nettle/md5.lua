require "resty.nettle.types.md5"

local lib          = require "resty.nettle.library"
local ffi          = require "ffi"
local ffi_new      = ffi.new
local ffi_typeof   = ffi.typeof
local ffi_cdef     = ffi.cdef
local ffi_str      = ffi.string
local setmetatable = setmetatable

ffi_cdef[[
void nettle_md5_init(struct md5_ctx *ctx);
void nettle_md5_update(struct md5_ctx *ctx, size_t length, const uint8_t *data);
void nettle_md5_digest(struct md5_ctx *ctx, size_t length, uint8_t *digest);
]]

local ctx = ffi_typeof "MD5_CTX[1]"
local buf = ffi_new("uint8_t[?]", 16)
local md5 = setmetatable({}, {
    __call = function(_, data, len)
        local context = ffi_new(ctx)
        lib.nettle_md5_init(context)
        lib.nettle_md5_update(context, len or #data, data)
        lib.nettle_md5_digest(context, 16, buf)
        return ffi_str(buf, 16)
    end
})
md5.__index = md5

function md5.new()
    local self = setmetatable({ context = ffi_new(ctx) }, md5)
    lib.nettle_md5_init(self.context)
    return self
end

function md5:update(data, len)
    return lib.nettle_md5_update(self.context, len or #data, data)
end

function md5:digest()
    lib.nettle_md5_digest(self.context, 16, buf)
    return ffi_str(buf, 16)
end

return md5