local string  = string
local type    = type
local gsub    = string.gsub
local rep     = string.rep
local sub     = string.sub
local padding = {}
function padding.pad(data, blocksize, optional)
    blocksize = blocksize or 16
    if type(blocksize) ~= "number" then
        return nil, "invalid block size data type"
    end
    if blocksize < 1 or blocksize > 256 then
        return nil, "invalid block size"
    end
    local ps = blocksize - #data % blocksize
    if optional and ps == blocksize then return data end
    return data .. "\x80" .. rep("\0", ps - 1)
end
function padding.unpad(data, blocksize)
    blocksize = blocksize or 16
    if type(blocksize) ~= "number" then
        return nil, "invalid block size data type"
    end
    if blocksize < 1 or blocksize > 256 then
        return nil, "invalid block size"
    end
    local len = #data
    if len % blocksize ~= 0 then
        return nil, "data length is not a multiple of the block size"
    end
    local d = gsub(data, "%z+$", "")
    if sub(d, -1) == "\x80" then
        return sub(d, 1, #d - 1)
    end
    return data
end
return padding
