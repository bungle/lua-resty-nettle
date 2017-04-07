require "resty.nettle.types.asn1"

local lib          = require "resty.nettle.hogweed"
local ffi          = require "ffi"
local ffi_new      = ffi.new
local ffi_str      = ffi.string
local ffi_cdef     = ffi.cdef
local ffi_typeof   = ffi.typeof
local setmetatable = setmetatable

ffi_cdef[[
enum asn1_iterator_result nettle_asn1_der_iterator_first(struct asn1_der_iterator *iterator, size_t length, const uint8_t *input);
enum asn1_iterator_result nettle_asn1_der_iterator_next(struct asn1_der_iterator *iterator);
enum asn1_iterator_result nettle_asn1_der_decode_constructed(struct asn1_der_iterator *i, struct asn1_der_iterator *contents);
enum asn1_iterator_result nettle_asn1_der_decode_constructed_last(struct asn1_der_iterator *i);
enum asn1_iterator_result nettle_asn1_der_decode_bitstring(struct asn1_der_iterator *i, struct asn1_der_iterator *contents);
enum asn1_iterator_result nettle_asn1_der_decode_bitstring_last(struct asn1_der_iterator *i);
int nettle_asn1_der_get_uint32(struct asn1_der_iterator *i, uint32_t *x);
]]


local ctx = ffi_typeof "struct asn1_der_iterator"
local asn1 = {}

asn1.__index = asn1

function asn1.new(input)
    local self = setmetatable({ context = ffi_new(ctx) }, asn1)
    self.state = lib.nettle_asn1_der_iterator_first(self.context, #input, input)
    return self
end

return asn1
