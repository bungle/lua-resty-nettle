require "resty.nettle.types.cipher"
local lib      = require "resty.nettle.library"
local ffi      = require "ffi"
local ffi_str  = ffi.string
local tonumber = tonumber
local ciphers  = {}
do
    local i, cs = 0, lib.nettle_ciphers
    while cs[i] ~= nil do
        local cipher = {
            name            = ffi_str(cs[i].name),
            context_size    = tonumber(cs[i].context_size),
            block_size      = tonumber(cs[i].block_size),
            key_size        = tonumber(cs[i].key_size),
            set_encrypt_key = cs[i].set_encrypt_key,
            set_decrypt_key = cs[i].set_decrypt_key,
            encrypt         = cs[i].encrypt,
            decrypt         = cs[i].decrypt
        }
        ciphers[i+1] = cipher
        ciphers[cipher.name] = cipher
        i=i+1
    end
end
return {
    ciphers = ciphers
}
