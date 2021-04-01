local types = require "resty.nettle.types.common"
local context = require "resty.nettle.types.sha3"
local lib = require "resty.nettle.library"
local ffi = require "ffi"
local ffi_new = ffi.new
local ffi_str = ffi.string
local setmetatable = setmetatable

local hashes = {
  shake256 = {
    length = 32,
    context = context.sha3_256,
    init = lib.nettle_sha3_256_init,
    update = lib.nettle_sha3_256_update,
    digest = lib.nettle_sha3_256_shake
  },
}

hashes[256] = hashes.shake256

local sha3shake = {}
sha3shake.__index = sha3shake

function sha3shake:update(data, len)
  return self.hash.update(self.context, len or #data, data)
end

function sha3shake:digest(digest_len)
  local length = digest_len or self.length
  local buffer = types.buffers(length)
  local hash = self.hash
  hash.digest(self.context, length, buffer)
  return ffi_str(buffer, length)
end

local function factory(hash)
  return setmetatable({
    new = function()
      local ctx = ffi_new(hash.context)
      hash.init(ctx)
      return setmetatable({ context = ctx, hash = hash }, sha3shake)
    end
  }, {
    __call = function(_, data, len, digest_len)
      local ctx = ffi_new(hash.context)
      hash.init(ctx)
      hash.update(ctx, len or #data, data)
      local length = digest_len or hash.length
      local buffer = types.buffers(length)
      hash.digest(ctx, length, buffer)
      return ffi_str(buffer, length)
    end
  })
end

return setmetatable({
  shake256 = factory(hashes.shake256),
}, {
  __call = function(_, bits, data, len, digest_len)
    local hash = hashes[bits]
    if not hash then
      return nil, "the only supported SHA3-SHAKE algorithm is the 256 bit one"
    end
    local ctx = ffi_new(hash.context)
    hash.init(ctx)
    hash.update(ctx, len or #data, data, digest_len)
    local length = digest_len or hash.length
    local buffer = types.buffers(length)
    hash.digest(ctx, length, buffer)
    return ffi_str(buffer, length)
  end
})
