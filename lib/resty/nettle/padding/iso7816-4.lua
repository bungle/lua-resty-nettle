local assert = assert
local string = string
local type = type
local gsub = string.gsub
local rep = string.rep
local sub = string.sub
local padding = {}
function padding.pad(data, blocksize)
    blocksize = blocksize or 16
    assert(type(blocksize) == "number" and blocksize > 0 and blocksize < 257, "Invalid block size")
    local ps = blocksize - #data % blocksize
    if ps == 0 then
        ps = blocksize
    end
    return data .. "\x80" .. rep("\0", ps - 1)
end
function padding.unpad(data, blocksize)
    blocksize = blocksize or 16
    assert(type(blocksize) == "number" and blocksize > 0 and blocksize < 257, "Invalid block size")
    local len = #data
    assert(len % blocksize == 0, "Data's length is not a multiple of the block size")
    data = gsub(data, "%z+$", "")
    assert(sub(data, -1) == "\x80", "Invalid padding found")
    return sub(data, 1, #data - 1)
end
return padding