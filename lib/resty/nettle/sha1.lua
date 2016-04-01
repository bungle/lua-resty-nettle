require "resty.nettle.types.sha1"

local ffi          = require "ffi"
local ffi_new      = ffi.new
local ffi_typeof   = ffi.typeof
local ffi_cdef     = ffi.cdef
local ffi_str      = ffi.string
local setmetatable = setmetatable
local nettle       = require "resty.nettle"

ffi_cdef[[
void nettle_sha1_init(struct sha1_ctx *ctx);
void nettle_sha1_update(struct sha1_ctx *ctx, size_t length, const uint8_t *data);
void nettle_sha1_digest(struct sha1_ctx *ctx, size_t length, uint8_t *digest);
]]

local ctx = ffi_typeof "SHA1_CTX[1]"
local buf = ffi_new("uint8_t[?]", 20)
local sha1 = setmetatable({}, {
    __call = function(_, data, len)
        local context = ffi_new(ctx)
        nettle.nettle_sha1_init(context)
        nettle.nettle_sha1_update(context, len or #data, data)
        nettle.nettle_sha1_digest(context, 20, buf)
        return ffi_str(buf, 20)
    end
})
sha1.__index = sha1

function sha1.new()
    local self = setmetatable({ context = ffi_new(ctx) }, sha1)
    nettle.nettle_sha1_init(self.context)
    return self
end

function sha1:update(data, len)
    return nettle.nettle_sha1_update(self.context, len or #data, data)
end

function sha1:digest()
    nettle.nettle_sha1_digest(self.context, 20, buf)
    return ffi_str(buf, 20)
end

return sha1

