local string  = string
local gsub    = string.gsub
local rep     = string.rep
local padding = {}
function padding.pad(data)
    local n = #data % 4
    return n == 0 and data or (data .. rep("=", 4 - n))
end
function padding.unpad(data)
    local len = #data
    if len % 4 ~= 0 then
        return nil, "Data is incorrectly padded."
    end
    data = gsub(data, "=+$", "")
    local rem = len - #data
    if rem < 0 or rem > 2 then
        return nil, "Data has invalid padding."
    end
    return data
end
return padding
