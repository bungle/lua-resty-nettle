local types = require "resty.nettle.types.common"
local context = require "resty.nettle.types.sha2"
local lib = require "resty.nettle.library"
local ffi = require "ffi"
local ffi_new = ffi.new
local ffi_str = ffi.string
local lower = string.lower
local setmetatable = setmetatable

local hashes = {
  sha224 = {
    length = 28,
    context = context.sha256,
    buffer = types.uint8_t_28,
    init = lib.nettle_sha224_init,
    update = lib.nettle_sha256_update,
    digest = lib.nettle_sha224_digest
  },
  sha256 = {
    length = 32,
    context = context.sha256,
    buffer = types.uint8_t_32,
    init = lib.nettle_sha256_init,
    update = lib.nettle_sha256_update,
    digest = lib.nettle_sha256_digest
  },
  sha384 = {
    length = 48,
    context = context.sha512,
    buffer = types.uint8_t_48,
    init = lib.nettle_sha384_init,
    update = lib.nettle_sha512_update,
    digest = lib.nettle_sha384_digest
  },
  sha512 = {
    length = 64,
    context = context.sha512,
    buffer = types.uint8_t_64,
    init = lib.nettle_sha512_init,
    update = lib.nettle_sha512_update,
    digest = lib.nettle_sha512_digest
  },
  sha512_224 = {
    length = 28,
    context = context.sha512,
    buffer = types.uint8_t_28,
    init = lib.nettle_sha512_224_init,
    update = lib.nettle_sha512_update,
    digest = lib.nettle_sha512_224_digest
  },
  sha512_256 = {
    length = 32,
    context = context.sha512,
    buffer = types.uint8_t_32,
    init = lib.nettle_sha512_256_init,
    update = lib.nettle_sha512_update,
    digest = lib.nettle_sha512_256_digest
  },
}

local sha2 = {}
sha2.__index = sha2

function sha2:update(data, len)
  return self.hash.update(self.context, len or #data, data)
end

function sha2:digest()
  local hash = self.hash
  hash.digest(self.context, hash.length, hash.buffer)
  return ffi_str(hash.buffer, hash.length)
end

local function factory(hash)
  return setmetatable({
    new = function()
      local ctx = ffi_new(hash.context)
      hash.init(ctx)
      return setmetatable({ context = ctx, hash = hash }, sha2)
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
  sha224 = factory(hashes.sha224),
  sha256 = factory(hashes.sha256),
  sha384 = factory(hashes.sha384),
  sha512 = factory(hashes.sha512),
  sha512_224 = factory(hashes.sha512_224),
  sha512_256 = factory(hashes.sha512_256)
}, {
  __call = function(_, algorithm, data, len)
    local hash = hashes[lower(algorithm)]
    if not hash then
      return nil, "the supported SHA2 algorithms are SHA224, SHA256, SHA384, SHA512, SHA512_224, and SHA512_256"
    end
    local ctx = ffi_new(hash.context)
    hash.init(ctx)
    hash.update(ctx, len or #data, data)
    hash.digest(ctx, hash.length, hash.buffer)
    return ffi_str(hash.buffer, hash.length)
  end
})
