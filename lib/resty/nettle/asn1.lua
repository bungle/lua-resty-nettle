require "resty.nettle.types.asn1"

local ffi          = require "ffi"
local ffi_cdef     = ffi.cdef

ffi_cdef[[
enum asn1_iterator_result asn1_der_iterator_first(struct asn1_der_iterator *iterator, size_t length, const uint8_t *input);
enum asn1_iterator_result asn1_der_iterator_next(struct asn1_der_iterator *iterator);
enum asn1_iterator_result asn1_der_decode_constructed(struct asn1_der_iterator *i, struct asn1_der_iterator *contents);
enum asn1_iterator_result asn1_der_decode_constructed_last(struct asn1_der_iterator *i);
enum asn1_iterator_result asn1_der_decode_bitstring(struct asn1_der_iterator *i, struct asn1_der_iterator *contents);
enum asn1_iterator_result asn1_der_decode_bitstring_last(struct asn1_der_iterator *i);
int asn1_der_get_uint32(struct asn1_der_iterator *i, uint32_t *x);
]]
