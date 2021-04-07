local ed25519 = require "resty.nettle.ed25519-sha512"
local ed448 = require "resty.nettle.ed448-shake256"

local eddsa = {}

function eddsa.public_key(pri)
  if not pri then
    return nil, "the EdDSA public key cannot be extracted without private key"
  end
  local len = #pri
  if len == 32 then
    return ed25519.public_key(pri)
  elseif len == 57 then
    return ed448.public_key(pri)
  else
    return nil, "the EdDSA supported private key sizes are 256 bits (Ed25519) and 456 bits (Ed448)"
  end
end

function eddsa.sign(pub, pri, msg)
  if not pri then
    return nil, "the EdDSA signing is not possible without private key"
  end
  local len = #pri
  if len == 32 then
    return ed25519.sign(pub, pri, msg)
  elseif len == 57 then
    return ed448.sign(pub, pri, msg)
  else
    return nil, "the EdDSA supported private key sizes are 256 bits (Ed25519) and 456 bits (Ed448)"
  end
end

function eddsa.verify(pub, msg, sig)
  if not pub then
    return nil, "the EdDSA signature verification is not possible without public key"
  end
  local len = #pub
  if len == 32 then
    return ed25519.verify(pub, msg, sig)
  elseif len == 57 then
    return ed448.verify(pub, msg, sig)
  else
    return nil, "the EdDSA supported public key sizes are 256 bits (Ed25519) and 456 bits (Ed448)"
  end
end

return eddsa
