local ffi          = require "ffi"
local ffi_new      = ffi.new
local ffi_typeof   = ffi.typeof
local ffi_cdef     = ffi.cdef
local ffi_str      = ffi.string
local setmetatable = setmetatable
local nettle       = require "resty.nettle"

ffi_cdef[[
typedef struct md2_ctx {
  uint8_t C[16];
  uint8_t X[48];
  uint8_t block[16];
  unsigned index;
} MD2_CTX;
void nettle_md2_init(struct md2_ctx *ctx);
void nettle_md2_update(struct md2_ctx *ctx, size_t length, const uint8_t *data);
void nettle_md2_digest(struct md2_ctx *ctx, size_t length, uint8_t *digest);
]]

local ctx = ffi_typeof "MD2_CTX[1]"
local buf = ffi_new("uint8_t[?]", 16)
local md2 = setmetatable({}, {
    __call = function(_, data, len)
        local context = ffi_new(ctx)
        nettle.nettle_md2_init(context)
        nettle.nettle_md2_update(context, len or #data, data)
        nettle.nettle_md2_digest(context, 16, buf)
        return ffi_str(buf, 16)
    end
})
md2.__index = md2

function md2.new()
    local self = setmetatable({ context = ffi_new(ctx) }, md2)
    nettle.nettle_md2_init(self.context)
    return self
end

function md2:update(data, len)
    return nettle.nettle_md2_update(self.context, len or #data, data)
end

function md2:digest()
    nettle.nettle_md2_digest(self.context, 16, buf)
    return ffi_str(buf, 16)
end

return md2