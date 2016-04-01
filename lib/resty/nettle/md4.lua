local ffi          = require "ffi"
local ffi_new      = ffi.new
local ffi_typeof   = ffi.typeof
local ffi_cdef     = ffi.cdef
local ffi_str      = ffi.string
local setmetatable = setmetatable
local nettle       = require "resty.nettle"

ffi_cdef[[
typedef struct md4_ctx {
  uint32_t state[16];
  uint64_t count;
  uint8_t block[64];
  unsigned index;
} MD4_CTX;
void nettle_md4_init(struct md4_ctx *ctx);
void nettle_md4_update(struct md4_ctx *ctx, size_t length, const uint8_t *data);
void nettle_md4_digest(struct md4_ctx *ctx, size_t length, uint8_t *digest);
]]

local ctx = ffi_typeof "MD4_CTX[1]"
local buf = ffi_new("uint8_t[?]", 16)
local md4 = setmetatable({}, {
    __call = function(_, data, len)
        local context = ffi_new(ctx)
        nettle.nettle_md4_init(context)
        nettle.nettle_md4_update(context, len or #data, data)
        nettle.nettle_md4_digest(context, 16, buf)
        return ffi_str(buf, 16)
    end
})
md4.__index = md4

function md4.new()
    local self = setmetatable({ context = ffi_new(ctx) }, md4)
    nettle.nettle_md4_init(self.context)
    return self
end

function md4:update(data, len)
    return nettle.nettle_md4_update(self.context, len or #data, data)
end

function md4:digest()
    nettle.nettle_md4_digest(self.context, 16, buf)
    return ffi_str(buf, 16)
end

return md4