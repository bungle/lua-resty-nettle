local ffi = require "ffi"
local ffi_new = ffi.new
local ffi_typeof = ffi.typeof
local ffi_fill = ffi.fill

local types = {
  size_t = ffi_typeof "size_t[?]",
  uint8_t = ffi_typeof "uint8_t[?]",
  uint32_t = ffi_typeof "uint32_t[?]",
  char = ffi_typeof "char[?]",
}

local predefined_a = {
  [1] = ffi_new(types.uint8_t, 1),
  [4] = ffi_new(types.uint8_t, 4),
  [8] = ffi_new(types.uint8_t, 8),
  [12] = ffi_new(types.uint8_t, 12),
  [16] = ffi_new(types.uint8_t, 16),
  [20] = ffi_new(types.uint8_t, 20),
  [24] = ffi_new(types.uint8_t, 24),
  [28] = ffi_new(types.uint8_t, 28),
  [32] = ffi_new(types.uint8_t, 32),
  [48] = ffi_new(types.uint8_t, 48),
  [56] = ffi_new(types.uint8_t, 56),
  [57] = ffi_new(types.uint8_t, 57),
  [61] = ffi_new(types.uint8_t, 61),
  [64] = ffi_new(types.uint8_t, 64),
  [114] = ffi_new(types.uint8_t, 114),
}

local predefined_b = {
  [1] = ffi_new(types.uint8_t, 1),
  [4] = ffi_new(types.uint8_t, 4),
  [8] = ffi_new(types.uint8_t, 8),
  [12] = ffi_new(types.uint8_t, 12),
  [16] = ffi_new(types.uint8_t, 16),
  [20] = ffi_new(types.uint8_t, 20),
  [24] = ffi_new(types.uint8_t, 24),
  [28] = ffi_new(types.uint8_t, 28),
  [32] = ffi_new(types.uint8_t, 32),
  [48] = ffi_new(types.uint8_t, 48),
  [56] = ffi_new(types.uint8_t, 56),
  [57] = ffi_new(types.uint8_t, 57),
  [61] = ffi_new(types.uint8_t, 61),
  [64] = ffi_new(types.uint8_t, 64),
  [114] = ffi_new(types.uint8_t, 114),
}

return {
  size_t = types.size_t,
  size_t_8 = ffi_new(types.size_t, 1),
  uint8_t = types.uint8_t,
  uint8_t_1 = predefined_a[1],
  uint8_t_4 = predefined_a[4],
  uint8_t_8 = predefined_a[8],
  uint8_t_12 = predefined_a[12],
  uint8_t_16 = predefined_a[16],
  uint8_t_20 = predefined_a[20],
  uint8_t_24 = predefined_a[24],
  uint8_t_28 = predefined_a[28],
  uint8_t_32 = predefined_a[32],
  uint8_t_48 = predefined_a[48],
  uint8_t_56 = predefined_a[56],
  uint8_t_57 = predefined_a[57],
  uint8_t_61 = predefined_a[61],
  uint8_t_64 = predefined_a[64],
  uint8_t_114 = predefined_a[114],
  uint32_t = types.uint32_t,
  char = types.char,
  char_2 = ffi_new(types.char, 2),
  char_3 = ffi_new(types.char, 3),
  buffers = function(size_a, size_b)
    local a = predefined_a[size_a] or ffi_new(types.uint8_t, size_a)
    local b
    if size_b then
      b = predefined_b[size_b] or ffi_new(types.uint8_t, size_b)
    end
    return a, b
  end,
  zerobuffers = function(size_a, size_b)
    local a = predefined_a[size_a]
    if a then
      ffi_fill(a, size_a)
    else
      a = ffi_new(types.uint8_t, size_a)
    end
    local b
    if size_b then
      b = predefined_a[size_b]
      if b then
        ffi_fill(b, size_b)
      else
        b = ffi_new(types.uint8_t, size_b)
      end
    end
    return a, b
  end
}
