# Changelog

All notable changes to `lua-resty-nettle` will be documented in this file.

## [0.100]
### Changed
- Added safeguards on missing ECC curves.
- Automatically calculate, if not provided, RSA a, b, c.
  (see [#11](https://github.com/bungle/lua-resty-nettle/issues/11),
   thanks [@hcaihao](https://github.com/hcaihao))
- Error messages without ending dot and in lowercase.

## [0.99]
### Added
- A more robust dynamic library loading.
  (see [#10](https://github.com/bungle/lua-resty-nettle/issues/10),
   thanks [@hcaihao](https://github.com/hcaihao))

## [0.98]
### Changed
- No asserts / errors anymore, all the functions return nil, error message
  on errors.
  
### Added  
- Added support for RSA-PSS signing algorithms.
- Added support for ECC.
- Added support for ECDSA.

### Fixed
- Base64 padding related fixes.

## [0.97] 
### Added
- Added RSA signing algorithms (MD5, SHA1, SHA256 and SHA512).
- Added CBC and CTR modes to Twofish.
- Added curve25519.

## [0.96] - 2016-11-22
### Added
- Support for the official OpenResty package manager (opm).
- Added version.lua file.
- Added version information in lua-resty-nettle.

### Changed
- Moved nettle.lua to nettle/library.lua.
- Implemented nettle.lua that autoloads everything.
