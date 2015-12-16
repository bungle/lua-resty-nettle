require "resty.nettle.types.aes"
require "resty.nettle.types.sha2"

local ffi          = require "ffi"
local ffi_new      = ffi.new
local ffi_typeof   = ffi.typeof
local ffi_cdef     = ffi.cdef
local ffi_str      = ffi.string
local assert       = assert
local rawget       = rawget
local getmetatable = getmetatable
local setmetatable = setmetatable
local nettle       = require "resty.nettle"
local knuth        = require "resty.nettle.knuth-lfib"

ffi_cdef[[
enum yarrow_pool_id { YARROW_FAST = 0, YARROW_SLOW = 1 };
typedef struct yarrow_source {
  uint32_t estimate[2];
  enum yarrow_pool_id next;
} YARROW_SOURCE;
typedef struct yarrow256_ctx {
  struct sha256_ctx pools[2];
  int seeded;
  struct aes256_ctx key;
  uint8_t counter[16];
  unsigned nsources;
  struct yarrow_source *sources;
} YARROW256_CTX;
void nettle_yarrow256_init(struct yarrow256_ctx *ctx, unsigned nsources, struct yarrow_source *sources);
void nettle_yarrow256_seed(struct yarrow256_ctx *ctx, size_t length, const uint8_t *seed_file);
int  nettle_yarrow256_update(struct yarrow256_ctx *ctx, unsigned source, unsigned entropy, size_t length, const uint8_t *data);
void nettle_yarrow256_random(struct yarrow256_ctx *ctx, size_t length, uint8_t *dst);
int  nettle_yarrow256_is_seeded(struct yarrow256_ctx *ctx);
unsigned nettle_yarrow256_needed_sources(struct yarrow256_ctx *ctx);
void nettle_yarrow256_fast_reseed(struct yarrow256_ctx *ctx);
void nettle_yarrow256_slow_reseed(struct yarrow256_ctx *ctx);
]]

local uint8t = ffi_typeof "uint8_t[?]"
local ctx256 = ffi_typeof "YARROW256_CTX[1]"

local yarrow = { func = nettle.nettle_yarrow256_random }
yarrow.__index = function(t, k)
    if k == "seeded" then
        return nettle.nettle_yarrow256_is_seeded(t.context) == 1
    elseif k == "sources" then
        return nettle.nettle_yarrow256_needed_sources(t.context)
    end
    return rawget(getmetatable(t), k)
end

function yarrow.context(seed)
    local context = ffi_new(ctx256)
    nettle.nettle_yarrow256_init(context, 0, nil)
    if not seed then
        seed = knuth.new():random(32)
    end
    local len = #seed
    assert(len > 31, "Seed data length should be at least 32 bytes, but it can be larger.")
    nettle.nettle_yarrow256_seed(context, len, seed)
    return context
end

function yarrow.new(seed)
    local self = setmetatable({ context = ffi_new(ctx256) }, yarrow)
    nettle.nettle_yarrow256_init(self.context, 0, nil)
    if seed then
        self:seed(seed)
    end
    return self
end

function yarrow:seed(data)
    local len = #data
    assert(len > 31, "Seed data length should be at least 32 bytes, but it can be larger.")
    nettle.nettle_yarrow256_seed(self.context, len, data)
end

function yarrow:fast_reseed()
    return nettle.nettle_yarrow256_fast_reseed(self.context)
end

function yarrow:slow_reseed()
    return nettle.nettle_yarrow256_slow_reseed(self.context)
end

function yarrow:random(length)
    local buffer = ffi_new(uint8t, length)
    nettle.nettle_yarrow256_random(self.context, length, buffer)
    return ffi_str(buffer, length)
end

return yarrow