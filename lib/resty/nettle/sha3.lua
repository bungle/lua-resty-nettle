local types = require "resty.nettle.types.common"
local context = require "resty.nettle.types.sha3"
local lib = require "resty.nettle.library"
local ffi = require "ffi"
local ffi_new = ffi.new
local ffi_str = ffi.string
local setmetatable = setmetatable

local hashes = {
  sha3_224 = {
    length = 28,
    context = context.sha3_224,
    buffer = types.uint8_t_28,
    init = lib.nettle_sha3_224_init,
    update = lib.nettle_sha3_224_update,
    digest = lib.nettle_sha3_224_digest
  },
  sha3_256 = {
    length = 32,
    context = context.sha3_256,
    buffer = types.uint8_t_32,
    init = lib.nettle_sha3_256_init,
    update = lib.nettle_sha3_256_update,
    digest = lib.nettle_sha3_256_digest
  },
  sha3_384 = {
    length = 48,
    context = context.sha3_384,
    buffer = types.uint8_t_48,
    init = lib.nettle_sha3_384_init,
    update = lib.nettle_sha3_384_update,
    digest = lib.nettle_sha3_384_digest
  },
  sha3_512 = {
    length = 64,
    context = context.sha3_512,
    buffer = types.uint8_t_64,
    init = lib.nettle_sha3_512_init,
    update = lib.nettle_sha3_512_update,
    digest = lib.nettle_sha3_512_digest
  },
}

hashes[224] = hashes.sha3_224
hashes[256] = hashes.sha3_256
hashes[384] = hashes.sha3_384
hashes[512] = hashes.sha3_512

local sha3 = {}
sha3.__index = sha3

function sha3:update(data, len)
  return self.hash.update(self.context, len or #data, data)
end

function sha3:digest()
  local hash = self.hash
  hash.digest(self.context, hash.length, hash.buffer)
  return ffi_str(hash.buffer, hash.length)
end

local function factory(hash)
  return setmetatable({
    new = function()
      local ctx = ffi_new(hash.context)
      hash.init(ctx)
      return setmetatable({ context = ctx, hash = hash }, sha3)
    end
  }, {
    __call = function(_, data, len)
      local ctx = ffi_new(hash.context)
      hash.init(ctx)
      hash.update(ctx, len or #data, data)
      hash.digest(ctx, hash.length, hash.buffer)
      return ffi_str(hash.buffer, hash.length)
    end
  })
end

return setmetatable({
  sha224 = factory(hashes.sha3_224),
  sha256 = factory(hashes.sha3_256),
  sha384 = factory(hashes.sha3_384),
  sha512 = factory(hashes[512])
}, {
  __call = function(_, bits, data, len)
    local hash = hashes[bits]
    if not hash then
      return nil, "the supported SHA3 algorithm output sizes are 224, 256, 384, and 512 bits"
    end
    local ctx = ffi_new(hash.context)
    hash.init(ctx)
    hash.update(ctx, len or #data, data)
    hash.digest(ctx, hash.length, hash.buffer)
    return ffi_str(hash.buffer, hash.length)
  end
})
