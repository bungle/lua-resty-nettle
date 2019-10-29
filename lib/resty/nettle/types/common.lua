local ffi = require "ffi"
local ffi_new = ffi.new
local ffi_typeof = ffi.typeof

local types = {
  size_t = ffi_typeof "size_t[?]",
  uint8_t = ffi_typeof "uint8_t[?]",
  uint32_t = ffi_typeof "uint32_t[?]",
  char = ffi_typeof "char[?]",
}

return {
  size_t = types.size_t,
  size_t_8 = ffi_new(types.size_t, 1),
  uint8_t = types.uint8_t,
  uint8_t_1 = ffi_new(types.uint8_t, 1),
  uint8_t_4 = ffi_new(types.uint8_t, 4),
  uint8_t_8 = ffi_new(types.uint8_t, 8),
  uint8_t_12 = ffi_new(types.uint8_t, 12),
  uint8_t_16 = ffi_new(types.uint8_t, 16),
  uint8_t_20 = ffi_new(types.uint8_t, 20),
  uint8_t_28 = ffi_new(types.uint8_t, 28),
  uint8_t_32 = ffi_new(types.uint8_t, 32),
  uint8_t_48 = ffi_new(types.uint8_t, 48),
  uint8_t_64 = ffi_new(types.uint8_t, 64),
  uint32_t = types.uint32_t,
  char = types.char,
  char_2 = ffi_new(types.char, 2),
  char_3 = ffi_new(types.char, 3),
}
