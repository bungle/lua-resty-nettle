-- TODO: THIS IS NOT DONE, IT IS NOT FULLY IMPLEMENTED.

require "resty.nettle.types.asn1"

local lib        = require "resty.nettle.hogweed"
local band       = require "bit".band
local ffi        = require "ffi"
local ffi_new    = ffi.new
local ffi_str    = ffi.string
local ffi_cdef   = ffi.cdef
local ffi_typeof = ffi.typeof
local tonumber   = tonumber
local floor      = math.floor
local fmod       = math.fmod

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
local uint = ffi_new "uint32_t[1]"

local decoders = {
    [lib.ASN1_BOOLEAN]         = function(context)
    end,
    [lib.ASN1_INTEGER]         = function(context)
    end,
    [lib.ASN1_BITSTRING]       = function(context)
    end,
    [lib.ASN1_OCTETSTRING]     = function(context)
    end,
    [lib.ASN1_NULL]            = function(context)
    end,
    [lib.ASN1_IDENTIFIER]      = function(context)
    end,
    [lib.ASN1_REAL]            = function(context)
    end,
    [lib.ASN1_ENUMERATED]      = function(context)
    end,
    [lib.ASN1_UTF8STRING]      = function(context)
    end,
    [lib.ASN1_SEQUENCE]        = function(context)
    end,
    [lib.ASN1_SET]             = function(context)
    end,
    [lib.ASN1_PRINTABLESTRING] = function(context)
    end,
    [lib.ASN1_TELETEXSTRING]   = function(context)
    end,
    [lib.ASN1_IA5STRING]       = function(context)
    end,
    [lib.ASN1_UTC]             = function(context)
    end,
    [lib.ASN1_UNIVERSALSTRING] = function(context)
    end,
    [lib.ASN1_BMPSTRING]       = function(context)
    end,
}


local function integer(context)
    lib.nettle_asn1_der_get_uint32(context, uint)
    return tonumber(uint[0])
end

local function identifier(context)
    local oid = {}
    local ind = 0
    local pos = 0
    local lst = context.length - 1
    local str = context.data
    if pos <= lst then
        local oct = str[pos]
        oid[2] = fmod(oct, 40)
        oid[1] = floor((oct - oid[2]) / 40)
        ind = 2
        pos = pos + 1
    end
    while pos <= lst do
        local c = 0
        local oct
        repeat
            oct = str[pos]
            pos = pos + 1
            c = c * 128 + band(0x7F, oct)
        until oct < 128
        ind = ind + 1
        oid[ind] = c
    end
    return oid
end

local asn1 = {}
asn1.__index = asn1

local function parse(state)
    local i = 1
    while i > 0 do
        if state[i][2] == lib.ASN1_ITERATOR_CONSTRUCTED then
            if state[i][1].pos == state[i][1].buffer_length then
                state[i][2] = lib.nettle_asn1_der_decode_constructed_last(state[i][1])
            else
                i = i + 1
                state[i] = { ffi_new(ctx) }
                state[i][2] = lib.nettle_asn1_der_decode_constructed(state[i-1][1], state[i][1])
            end
        elseif state[i][2] == lib.ASN1_ITERATOR_PRIMITIVE then
            local t = state[i][1].type
            if t == lib.ASN1_BOOLEAN then
                print "ASN1_BOOLEAN"
            elseif t == lib.ASN1_INTEGER then
                print "ASN1_INTEGER"
                print("  number: ", integer(state[i][1]))
            elseif t == lib.ASN1_BITSTRING then
                print "ASN1_BITSTRING"

                if state[i][1].pos == state[i][1].buffer_length then
                    --state[i][2] = lib.nettle_asn1_der_decode_bitstring_last(state[i][1])
                    --state[i][1] = state[i][1]
                else
                    local s2  = {{ ffi_new(ctx) }}
                    s2[1][2] = lib.nettle_asn1_der_decode_bitstring(state[i][1], s2[1][1])
                    parse(s2)
                end


            elseif t == lib.ASN1_OCTETSTRING then
                print "ASN1_OCTETSTRING"
                print("    data: ", ffi_str(state[i][1].data, state[i][1].length))
            elseif t == lib.ASN1_NULL then
                print "ASN1_NULL"
            elseif t == lib.ASN1_IDENTIFIER then
                print "ASN1_IDENTIFIER"
                print("    data: ", table.concat(identifier(state[i][1]), "."))
            elseif t == lib.ASN1_REAL then
                print "ASN1_REAL"
                print("    data: ", ffi_str(state[i][1].data, state[i][1].length))
            elseif t == lib.ASN1_ENUMERATED then
                print "ASN1_ENUMERATED"
                print("    data: ", ffi_str(state[i][1].data, state[i][1].length))
            elseif t == lib.ASN1_UTF8STRING then
                print "ASN1_UTF8STRING"
                print("    data: ", ffi_str(state[i][1].data, state[i][1].length))
            elseif t == lib.ASN1_SEQUENCE then
                print "ASN1_SEQUENCE"
            elseif t == lib.ASN1_SET then
                print "ASN1_SET"
            elseif t == lib.ASN1_PRINTABLESTRING then
                print "ASN1_PRINTABLESTRING"
                print("    data: ", ffi_str(state[i][1].data, state[i][1].length))
            elseif t == lib.ASN1_TELETEXSTRING then
                print "ASN1_TELETEXSTRING"
            elseif t == lib.ASN1_IA5STRING then
                print "ASN1_IA5STRING"
                print("    data: ", ffi_str(state[i][1].data, state[i][1].length))
            elseif t == lib.ASN1_UTC then
                print "ASN1_UTC"
                print("    data: ", ffi_str(state[i][1].data, state[i][1].length))
            elseif t == lib.ASN1_UNIVERSALSTRING then
                print "ASN1_UNIVERSALSTRING"
                print("    data: ", ffi_str(state[i][1].data, state[i][1].length))
            elseif t == lib.ASN1_BMPSTRING then
                print "ASN1_BMPSTRING"
                print("    data: ", ffi_str(state[i][1].data, state[i][1].length))
            else
                print "UNKNOWN"
            end
            state[i][2] = lib.nettle_asn1_der_iterator_next(state[i][1])
        elseif state[i][2] == lib.ASN1_ITERATOR_END then
            print("ASN1_ITERATOR_END")
            state[i] = nil
            i = i - 1
            if i ~= 0 then
                state[i][2] = lib.ASN1_ITERATOR_PRIMITIVE
            end
        elseif state[i][2] == lib.ASN1_ITERATOR_ERROR then
            print("ASN1_ITERATOR_ERROR")
            state[i] = nil
            i = i - 1
        end
    end

end

function asn1.decode(input)
    local state  = {{ ffi_new(ctx) }}
    state[1][2] = lib.nettle_asn1_der_iterator_first(state[1][1], #input, input)
    parse(state)
end

return asn1
