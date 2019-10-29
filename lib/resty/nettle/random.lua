if ngx then
  local random = require "resty.random"

  local ffi = require "ffi"
  local C = ffi.C

  return {
    bytes = random.bytes,
    context = nil,
    func = function(_, length, dst)
      C.RAND_bytes(dst, length)
    end
  }
end

local knuth = require "resty.nettle.knuth-lfib"

math.randomseed(os.clock() * 1000000 * os.time())

math.random()
math.random()
math.random()

local k = knuth.new(math.random() * 100000000000000)

return {
  bytes = function(n)
    return k:random(n)
  end,
  context = k.context,
  func = knuth.func,
}
