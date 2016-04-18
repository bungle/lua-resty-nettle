require "resty.nettle.types.aead"
local ffi      = require "ffi"
local nettle   = require "resty.nettle"
local ffi_str  = ffi.string
local tonumber = tonumber
local aeads = {}
do
    local i, as = 0, nettle.nettle_aeads
    while as[i] ~= nil do
        local aead = {
            name            = ffi_str(as[i].name),
            context_size    = tonumber(as[i].context_size),
            block_size      = tonumber(as[i].block_size),
            key_size        = tonumber(as[i].key_size),
            nonce_size      = tonumber(as[i].nonce_size),
            set_encrypt_key = as[i].set_encrypt_key,
            set_decrypt_key = as[i].set_decrypt_key,
            set_nonce       = as[i].set_nonce,
            update          = as[i].update,
            encrypt         = as[i].encrypt,
            decrypt         = as[i].decrypt,
            digest          = as[i].digest
        }
        aeads[i+1] = aead
        aeads[aead.name] = aead
        i=i+1
    end
end
return {
    aeads = aeads
}