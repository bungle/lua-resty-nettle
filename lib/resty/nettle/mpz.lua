require "resty.nettle.types.mpz"

local ffi        = require "ffi"
local ffi_gc     = ffi.gc
local ffi_str    = ffi.string
local ffi_new    = ffi.new
local ffi_load   = ffi.load
local ffi_cdef   = ffi.cdef
local ffi_typeof = ffi.typeof
local type       = type
local gmp        = ffi_load "gmp"

ffi_cdef[[
void   __gmpz_init(mpz_t);
void   __gmpz_clear(mpz_ptr);
size_t __gmpz_sizeinbase(const mpz_t op, int base);
char * __gmpz_get_str(char *str, int base, const mpz_t op);
int    __gmpz_set_str(mpz_t rop, const char *str, int base);
void   __gmpz_set_ui(mpz_t, unsigned long int iv);
]]

local ctx = ffi_typeof "mpz_t"
local chr = ffi_typeof "char[?]"

local mpz = {}
mpz.__index = mpz

function mpz.new(value, base)
    local context = ffi_gc(ffi_new(ctx), gmp.__gmpz_clear)
    gmp.__gmpz_init(context)
    if value then
        local ok, err = mpz.set(context, value, base)
        if not ok then
            return nil, err
        end
    end
    return context
end

function mpz.sizeof(op, base)
    return gmp.__gmpz_sizeinbase(op, base or 16)
end

function mpz.string(op, base)
    local l = mpz.sizeof(op, base)
    local b = ffi_new(chr, l + 2)
    return ffi_str(gmp.__gmpz_get_str(b, base or 16, op), l)
end

function mpz.set(op, value, base)
    local t = type(value)
    if t == "string" then
        if gmp.__gmpz_set_str(op, value, base or 16) ~= 0 then
            return nil, "Unable to set mpz_t value from a string."
        end
    elseif t == "number" then
        gmp.__gmpz_set_ui(op, value)
    else
        return nil, "Unable to set mpz_t value from an unsupported data type."
    end
    return true
end

return mpz
