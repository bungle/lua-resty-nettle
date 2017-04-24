# Changelog

All notable changes to `lua-resty-nettle` will be documented in this file.

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

### Change
- Moved nettle.lua to nettle/library.lua.
- Implemented nettle.lua that autoloads everything.
