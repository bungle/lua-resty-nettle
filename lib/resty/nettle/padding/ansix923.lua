local string  = string
local type    = type
local char    = string.char
local byte    = string.byte
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
    return data .. rep("\0", ps - 1) .. char(ps)
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
    local chr = sub(data, -1)
    local rem = byte(chr)
    if rem > 0 and rem <= blocksize then
        local chk = sub(data, -rem)
        if chk == rep("\0", rem - 1) .. chr then
            return sub(data, 1, len - rem)
        end
    end
    return data
end
return padding
