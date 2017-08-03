local ffi      = require "ffi"
local ffi_cdef = ffi.cdef

ffi_cdef[[
enum {
    ASN1_TYPE_CONSTRUCTED = 1 << 12,
    ASN1_CLASS_UNIVERSAL = 0,
    ASN1_CLASS_APPLICATION = 1 << 13,
    ASN1_CLASS_CONTEXT_SPECIFIC = 2 << 13,
    ASN1_CLASS_PRIVATE = 3 << 13,
    ASN1_CLASS_MASK = 3 << 13,
    ASN1_CLASS_SHIFT = 13,
};
enum asn1_type {
    ASN1_BOOLEAN = 1,
    ASN1_INTEGER = 2,
    ASN1_BITSTRING = 3,
    ASN1_OCTETSTRING = 4,
    ASN1_NULL = 5,
    ASN1_IDENTIFIER = 6,
    ASN1_REAL = 9,
    ASN1_ENUMERATED = 10,
    ASN1_UTF8STRING = 12,
    ASN1_SEQUENCE = 16 | ASN1_TYPE_CONSTRUCTED,
    ASN1_SET = 17 | ASN1_TYPE_CONSTRUCTED,
    ASN1_PRINTABLESTRING = 19,
    ASN1_TELETEXSTRING = 20,
    ASN1_IA5STRING = 22,
    ASN1_UTC = 23,
    ASN1_UNIVERSALSTRING = 28,
    ASN1_BMPSTRING = 30,
};
enum asn1_iterator_result {
    ASN1_ITERATOR_ERROR,
    ASN1_ITERATOR_PRIMITIVE,
    ASN1_ITERATOR_CONSTRUCTED,
    ASN1_ITERATOR_END,
};
struct asn1_der_iterator {
    size_t buffer_length;
    const uint8_t *buffer;
    size_t pos;
    enum asn1_type type;
    size_t length;
    const uint8_t *data;
};
]]
