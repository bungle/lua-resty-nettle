local assert  = assert
local string  = string
local ceil    = math.ceil
local gsub    = string.gsub
local rep     = string.rep
local padding = {}
function padding.pad(data)
    local l = #data
    local n = 4 * ceil(l/4) - l
    return n == 0 and data or (data .. rep("=", n))
end
function padding.unpad(data)
    local len = #data
    assert(len % 4 == 0, "Data is incorrectly padded")
    data = gsub(data, "=+$", "")
    local rem = len - #data
    assert(rem > -1 and rem <= 2, "Invalid padding found")
    return data
end
return padding
