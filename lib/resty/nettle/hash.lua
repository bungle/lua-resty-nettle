require "resty.nettle.types.hash"
local lib      = require "resty.nettle.library"
local ffi      = require "ffi"
local tonumber = tonumber
local ffi_str  = ffi.string
local hashes = {}
do
    local i, hs = 0, lib.nettle_hashes
    while hs[i] ~= nil do
        local hash = {
            name         = ffi_str(hs[i].name),
            context_size = tonumber(hs[i].context_size),
            block_size   = tonumber(hs[i].block_size),
            init         = hs[i].init,
            update       = hs[i].update,
            digest       = hs[i].digest
        }
        hashes[i+1] = hash
        hashes[hash.name] = hash
        i=i+1
    end
end
return {
    hashes = hashes
}