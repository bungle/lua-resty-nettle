local lib          = require "resty.nettle.library"
local ffi          = require "ffi"
local ffi_new      = ffi.new
local ffi_typeof   = ffi.typeof
local ffi_cdef     = ffi.cdef
local ffi_str      = ffi.string
local setmetatable = setmetatable

ffi_cdef[[
typedef struct gosthash94_ctx {
  uint32_t hash[8];
  uint32_t sum[8];
  uint8_t message[32];
  uint64_t length;
} GOSTHASH94_CTX;
void nettle_gosthash94_init(struct gosthash94_ctx *ctx);
void nettle_gosthash94_update(struct gosthash94_ctx *ctx, size_t length, const uint8_t *data);
void nettle_gosthash94_digest(struct gosthash94_ctx *ctx, size_t length, uint8_t *digest);
]]

local ctx = ffi_typeof "GOSTHASH94_CTX[1]"
local buf = ffi_new("uint8_t[?]", 32)
local gosthash94 = setmetatable({}, {
    __call = function(_, data, len)
        local context = ffi_new(ctx)
        lib.nettle_gosthash94_init(context)
        lib.nettle_gosthash94_update(context, len or #data, data)
        lib.nettle_gosthash94_digest(context, 32, buf)
        return ffi_str(buf, 32)
    end
})
gosthash94.__index = gosthash94

function gosthash94.new()
    local self = setmetatable({ context = ffi_new(ctx) }, gosthash94)
    lib.nettle_gosthash94_init(self.context)
    return self
end

function gosthash94:update(data, len)
    return lib.nettle_gosthash94_update(self.context, len or #data, data)
end

function gosthash94:digest()
    lib.nettle_gosthash94_digest(self.context, 32, buf)
    return ffi_str(buf, 32)
end

return gosthash94