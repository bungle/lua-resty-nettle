require "resty.nettle.types.ecdsa"

local random = require "resty.nettle.random"
local hogweed = require "resty.nettle.hogweed"
local dsa = require "resty.nettle.dsa"
local ecc = require "resty.nettle.ecc"
local setmetatable = setmetatable

local sig = dsa.signature.new()

local keypair = {}

function keypair.new(c)
  local p, err = ecc.point.new(c)
  if not p then
    return nil, err
  end

  local s
  s, err = ecc.scalar.new(c)
  if not s then
    return nil, err
  end

  hogweed.nettle_ecdsa_generate_keypair(p.context, s.context, random.context, random.func)

  return setmetatable({
    point = p,
    scalar = s,
  }, keypair)
end

local ecdsa = { signature = dsa.signature, point = ecc.point, scalar = ecc.scalar, keypair = keypair }

ecdsa.__index = ecdsa

function ecdsa.new(point, scalar)
  return setmetatable({ point = point, scalar = scalar }, ecdsa)
end

function ecdsa:verify(digest, signature)
  if hogweed.nettle_ecdsa_verify(self.point.context, #digest, digest, signature.context or signature) ~= 1 then
    return nil, "unable to ECDSA verify"
  end
  return true
end

function ecdsa:sign(digest, len)
  hogweed.nettle_ecdsa_sign(self.scalar.context, random.context, random.func, #digest, digest, sig.context)

  return {
    r = sig:r(len),
    s = sig:s(len),
  }
end

return ecdsa
