local string = string
local type = type
local gsub = string.gsub
local rep = string.rep
local padding = {}
function padding.pad(data, blocksize, optional)
    blocksize = blocksize or 16
    if type(blocksize) ~= "number" then
        return nil, "Invalid block size data type."
    end
    if blocksize < 1 or blocksize > 256 then
        return nil, "Invalid block size."
    end
    local ps = blocksize - #data % blocksize
    if optional and ps == blocksize then return data end
    return data .. rep("\0", ps)
end
function padding.unpad(data, blocksize)
    blocksize = blocksize or 16
    if type(blocksize) ~= "number" then
        return nil, "Invalid block size data type."
    end
    if blocksize < 1 or blocksize > 256 then
        return nil, "Invalid block size."
    end
    local len = #data
    if len % blocksize ~= 0 then
        return nil, "Data length is not a multiple of the block size."
    end
    data = gsub(data, "%z+$", "")
    local rem = len - #data
    if rem < 0 or rem > blocksize then
        return nil, "Data has invalid padding."
    end
    return data
end
return padding
