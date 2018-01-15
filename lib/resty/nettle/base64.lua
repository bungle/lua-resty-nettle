local lib          = require "resty.nettle.library"
local bit          = require "bit"
local ffi          = require "ffi"
local ffi_new      = ffi.new
local ffi_typeof   = ffi.typeof
local ffi_cdef     = ffi.cdef
local ffi_str      = ffi.string
local bnot         = bit.bnot
local band         = bit.band
local byte         = string.byte
local ceil         = math.ceil
local floor        = math.floor
local tonumber     = tonumber
local setmetatable = setmetatable

ffi_cdef[[
void   nettle_base64_encode_init   (struct base64_encode_ctx *ctx);
void   nettle_base64url_encode_init(struct base64_encode_ctx *ctx);
size_t nettle_base64_encode_single (struct base64_encode_ctx *ctx, char *dst, uint8_t src);
size_t nettle_base64_encode_update (struct base64_encode_ctx *ctx, char *dst, size_t length, const uint8_t *src);
size_t nettle_base64_encode_final  (struct base64_encode_ctx *ctx, char *dst);
void   nettle_base64_encode_raw    (char *dst, size_t length, const uint8_t *src);
void   nettle_base64_decode_init   (struct base64_decode_ctx *ctx);
void   nettle_base64url_decode_init(struct base64_decode_ctx *ctx);
int    nettle_base64_decode_single (struct base64_decode_ctx *ctx, uint8_t *dst, char src);
int    nettle_base64_decode_update (struct base64_decode_ctx *ctx, size_t *dst_length, uint8_t *dst, size_t src_length, const char *src);
int    nettle_base64_decode_final  (struct base64_decode_ctx *ctx);
]]

local ctxenc = ffi_typeof [[
struct base64_encode_ctx {
  const char *alphabet;
  unsigned short word;
  unsigned char bits;
}]]

local ctxdec =  ffi_typeof [[
struct base64_decode_ctx {
  const signed char *table;
  unsigned short word;
  unsigned char bits;
  unsigned char padding;
}]]

local length = ffi_new "size_t[1]"
local uint8t = ffi_typeof "uint8_t[?]"
local buf8   = ffi_new(uint8t, 1)

local chart = ffi_typeof "char[?]"
local char16  = ffi_new(chart, 2)
local char24  = ffi_new(chart, 3)

local encoder = {}
encoder.__index = encoder

function encoder.new(urlsafe)
    local ctx = ffi_new(ctxenc)
    if urlsafe then
        lib.nettle_base64url_encode_init(ctx)
    else
        lib.nettle_base64_encode_init(ctx)
    end
    return setmetatable({ context = ctx }, encoder)
end

function encoder:single(src)
    local len = lib.nettle_base64_encode_single(self.context, char16, byte(src))
    return ffi_str(char16, len), tonumber(len)
end

function encoder:update(src)
    local len = #src
    local dln = ceil(4 * len / 3)
    local dst = ffi_new(chart, dln)
    local len = lib.nettle_base64_encode_update(self.context, dst, len, src)
    return ffi_str(dst, len), tonumber(len)
end

function encoder:final()
    local len = lib.nettle_base64_encode_final(self.context, char24)
    return ffi_str(char24, len), tonumber(len)
end

local decoder = {}
decoder.__index = decoder

function decoder.new(urlsafe)
    local ctx = ffi_new(ctxdec)
    if urlsafe then
        lib.nettle_base64url_decode_init(ctx)
    else
        lib.nettle_base64_decode_init(ctx)
    end
    return setmetatable({ context = ctx }, decoder)
end

function decoder:single(src)
    local len = lib.nettle_base64_decode_single(self.context, buf8, byte(src))
    return ffi_str(buf8, len), len
end

function decoder:update(src)
    local len = #src
    local dln = floor(len * 3 / 4)
    local dst = ffi_new(uint8t, dln)
    if lib.nettle_base64_decode_update(self.context, length, dst, len, src) ~= 1 then
        return nil, "unable to decode base64 data"
    end
    local len = tonumber(length[0])
    return ffi_str(dst, len), len
end

function decoder:final()
    if lib.nettle_base64_decode_final(self.context) ~= 1 then
        return nil, "final padding of base64 is incorrect"
    end
    return true
end

local base64 = setmetatable({ encoder = encoder, decoder = decoder }, {
    __call = function(_, src)
        local len = #src
        local dln = ceil(4 * len / 3)
        local dst = ffi_new(chart, dln)
        lib.nettle_base64_encode_raw(dst, len, src)
        return ffi_str(dst, dln)
    end
})

function base64.encode(src, urlsafe)
    local ctx = ffi_new(ctxenc)
    if urlsafe then
        lib.nettle_base64url_encode_init(ctx)
    else
        lib.nettle_base64_encode_init(ctx)
    end
    local len = #src
    local dln = band((4 * len / 3) + 3, bnot(3))
    local dst = ffi_new(chart, dln)
    dst = ffi_str(dst, lib.nettle_base64_encode_update(ctx, dst, len, src))
    local fnl = lib.nettle_base64_encode_final(ctx, char24)
    if fnl > 0 then
        return dst .. ffi_str(char24, fnl)
    end
    return dst
end

function base64.decode(src, urlsafe)
    local ctx = ffi_new(ctxdec)
    local len = #src
    local dln = floor(len * 3 / 4)
    local dst = ffi_new(uint8t, dln)
    if urlsafe then
        lib.nettle_base64url_decode_init(ctx)
    else
        lib.nettle_base64_decode_init(ctx)
    end
    if lib.nettle_base64_decode_update(ctx, length, dst, len, src) ~= 1 then
        return nil, "unable to decode base64 data"
    end
    if lib.nettle_base64_decode_final(ctx) ~= 1 then
        return nil, "final padding of base64 is incorrect"
    end
    return ffi_str(dst, length[0])
end

function base64.urlencode(src)
    return base64.encode(src, true)
end

function base64.urldecode(src)
    return base64.decode(src, true)
end

return base64
