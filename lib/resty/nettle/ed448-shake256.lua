require "resty.nettle.types.ed448-shake256"

local types = require "resty.nettle.types.common"
local hogweed = require "resty.nettle.hogweed"
local ffi = require "ffi"
local ffi_str = ffi.string

local ed = {}

function ed.public_key(pri)
  if #pri ~= 57 then
    return nil, "the EdDSA448 SHAKE-256 supported key size is 456 bits"
  end
  hogweed.nettle_ed448_shake256_public_key(types.uint8_t_57, pri)
  return ffi_str(types.uint8_t_57, 57)
end

function ed.sign(pub, pri, msg)
  if pri and not pub then
    local err
    pub, err = ed.public_key(pri)
    if not pub then
      return nil, err
    end
  end
  if #pub ~= 57 then
    return nil, "the EdDSA448 SHAKE-256 supported public key size is 456 bits"
  end
  if #pri ~= 57 then
    return nil, "the EdDSA448 SHAKE-256 supported private key size is 456 bits"
  end
  hogweed.nettle_ed448_shake256_sign(pub, pri, #msg, msg, types.uint8_t_114)
  return ffi_str(types.uint8_t_114, 114)
end

function ed.verify(pub, msg, sig)
  if #pub ~= 57 then
    return nil, "the EdDSA448 SHAKE-256 supported public key size is 456 bits"
  end
  if #sig ~= 114 then
    return nil, "the EdDSA448 SHAKE-256 supported signature size is 912 bits"
  end
  if hogweed.nettle_ed448_shake256_verify(pub, #msg, msg, sig) ~= 1 then
    return nil, "unable to EdDSA448 SHAKE-256 verify"
  end
  return true
end

return ed
