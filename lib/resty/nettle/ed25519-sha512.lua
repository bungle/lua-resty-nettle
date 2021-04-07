require "resty.nettle.types.ed25519-sha512"

local types = require "resty.nettle.types.common"
local hogweed = require "resty.nettle.hogweed"
local ffi = require "ffi"
local ffi_str = ffi.string

local ed25519 = {}

function ed25519.public_key(pri)
  if not pri then
    return nil, "the EdDSA25519 SHA-512 public key cannot be extracted without private key"
  end
  if #pri ~= 32 then
    return nil, "the EdDSA25519 SHA-512 supported private key size is 256 bits"
  end
  hogweed.nettle_ed25519_sha512_public_key(types.uint8_t_32, pri)
  return ffi_str(types.uint8_t_32, 32)
end

function ed25519.sign(pub, pri, msg)
  if not pri then
    return nil, "the EdDSA25519 SHA-512 signing is not possible without private key"
  end
  if not pub then
    local err
    pub, err = ed25519.public_key(pri)
    if not pub then
      return nil, err
    end
  end
  if #pub ~= 32 then
    return nil, "the EdDSA25519 SHA-512 supported public key size is 256 bits"
  end
  if #pri ~= 32 then
    return nil, "the EdDSA25519 SHA-512 supported private key size is 256 bits"
  end
  hogweed.nettle_ed25519_sha512_sign(pub, pri, #msg, msg, types.uint8_t_64)
  return ffi_str(types.uint8_t_64, 64)
end

function ed25519.verify(pub, msg, sig)
  if not pub then
    return nil, "the EdDSA25519 SHA-512 signature verification is not possible without public key"
  end
  if not sig then
    return nil, "the EdDSA25519 SHA-512 signature verification is not possible without signature"
  end
  if #pub ~= 32 then
    return nil, "the EdDSA25519 SHA-512 supported public key size is 256 bits"
  end
  if #sig ~= 64 then
    return nil, "the EdDSA25519 SHA-512 supported signature size is 512 bits"
  end
  if hogweed.nettle_ed25519_sha512_verify(pub, #msg, msg, sig) ~= 1 then
    return nil, "unable to EdDSA25519 SHA-512 verify"
  end
  return true
end

return ed25519
