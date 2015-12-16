require "resty.nettle.types.gmp"

local ffi        = require "ffi"
local ffi_gc     = ffi.gc
local ffi_str    = ffi.string
local ffi_new    = ffi.new
local ffi_load   = ffi.load
local ffi_cdef   = ffi.cdef
local ffi_typeof = ffi.typeof
local type       = type
local assert     = assert
local gmp        = ffi_load "gmp"

ffi_cdef[[
void   __gmpz_init (mpz_t);
void   __gmpz_clear (mpz_t);
size_t __gmpz_sizeinbase (const mpz_t op, int base);
char * __gmpz_get_str (char *str, int base, const mpz_t op);
int    __gmpz_set_str (mpz_t rop, const char *str, int base);
void   __gmpz_set_ui (mpz_t, unsigned long int iv);
]]

local ctx = ffi_typeof "mpz_t"
local chr = ffi_typeof "char[?]"

local mpz = {}
mpz.__index = mpz

function mpz.context(str, base)
    local context = ffi_gc(ffi_new(ctx), gmp.__gmpz_clear)
    gmp.__gmpz_init(context)
    if str then
        assert(gmp.__gmpz_set_str(context, str, base or 16) == 0)
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
        return gmp.__gmpz_set_str(op, value, base or 16)
    elseif t == "number" then
        return gmp.__gmpz_set_ui(op, value)
    end
end

return mpz
