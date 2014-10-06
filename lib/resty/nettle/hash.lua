require "resty.nettle.types.hash"
local ffi      = require "ffi"
local nettle   = require "resty.nettle"
local ffi_str  = ffi.string
local ffi_new  = ffi.new

local hashes = {}

do
    local null = ffi_new("void * ")
    local i, hs = 0, nettle.nettle_hashes
    while hs[i] ~= null do
        local hash = {
            name         = ffi_str(hs[i].name),
            context_size = tonumber(hs[i].context_size),
            block_size   = tonumber(hs[i].block_size),
            init         = hs[i].init,
            update       = hs[i].update,
            digest       = hs[i].digest
        }
        hashes[i + 1] = hash
        hashes[hash.name] = hash
        i = i + 1
    end
end

return {
    hashes = hashes
}