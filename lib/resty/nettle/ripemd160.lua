require "resty.nettle.types.ripemd160"

local ffi          = require "ffi"
local ffi_new      = ffi.new
local ffi_typeof   = ffi.typeof
local ffi_cdef     = ffi.cdef
local ffi_str      = ffi.string
local setmetatable = setmetatable
local nettle       = require "resty.nettle"

ffi_cdef[[
void nettle_ripemd160_init(struct ripemd160_ctx *ctx);
void nettle_ripemd160_update(struct ripemd160_ctx *ctx, size_t length, const uint8_t *data);
void nettle_ripemd160_digest(struct ripemd160_ctx *ctx, size_t length, uint8_t *digest);
]]

local ctx = ffi_typeof "RIPEMD160_CTX[1]"
local buf = ffi_new("uint8_t[?]", 20)
local ripemd160 = setmetatable({}, {
    __call = function(_, data, len)
        local context = ffi_new(ctx)
        nettle.nettle_ripemd160_init(context)
        nettle.nettle_ripemd160_update(context, len or #data, data)
        nettle.nettle_ripemd160_digest(context, 20, buf)
        return ffi_str(buf, 20)
    end
})
ripemd160.__index = ripemd160

function ripemd160.new()
    local self = setmetatable({ context = ffi_new(ctx) }, ripemd160)
    nettle.nettle_ripemd160_init(self.context)
    return self
end

function ripemd160:update(data, len)
    return nettle.nettle_ripemd160_update(self.context, len or #data, data)
end

function ripemd160:digest()
    nettle.nettle_ripemd160_digest(self.context, 20, buf)
    return ffi_str(buf, 20)
end

return ripemd160