local lib          = require "resty.nettle.library"
local ffi          = require "ffi"
local ffi_new      = ffi.new
local ffi_typeof   = ffi.typeof
local ffi_cdef     = ffi.cdef
local ffi_str      = ffi.string
local setmetatable = setmetatable

ffi_cdef[[
typedef struct knuth_lfib_ctx {
  uint32_t x[100];
  unsigned index;
} KNUTH_LFIB_CTX;
void     nettle_knuth_lfib_init(struct knuth_lfib_ctx *ctx, uint32_t seed);
uint32_t nettle_knuth_lfib_get(struct knuth_lfib_ctx *ctx);
void     nettle_knuth_lfib_get_array(struct knuth_lfib_ctx *ctx, size_t n, uint32_t *a);
void     nettle_knuth_lfib_random(struct knuth_lfib_ctx *ctx, size_t n, uint8_t *dst);
]]

local uint8t  = ffi_typeof "uint8_t[?]"
local uint32t = ffi_typeof "uint32_t[?]"
local ctx = ffi_typeof "KNUTH_LFIB_CTX[1]"

local knuth = { func = lib.nettle_knuth_lfib_random }
knuth.__index = knuth

function knuth.context(seed)
    local context = ffi_new(ctx)
    lib.nettle_knuth_lfib_init(context, seed or 0)
    return context
end

function knuth.new(seed)
    local self = setmetatable({ context = ffi_new(ctx) }, knuth)
    lib.nettle_knuth_lfib_init(self.context, seed or 0)
    return self
end

function knuth:number()
    return lib.nettle_knuth_lfib_get(self.context)
end

function knuth:array(n)
    local b = ffi_new(uint32t, n)
    lib.nettle_knuth_lfib_get_array(self.context, n, b)
    local r = {}
    for i=1, n do r[i] = b[i-1] end
    return r
end

function knuth:random(n)
    local b = ffi_new(uint8t, n)
    lib.nettle_knuth_lfib_random(self.context, n, b)
    return ffi_str(b, n)
end

return knuth