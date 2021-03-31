# Changelog

All notable changes to `lua-resty-nettle` will be documented in this file.


## [1.6] - Upcoming
### Added
- Add Streebog hashing algorithms (256 and 512)
- Add PBKDF2 HMAC-SHA384 and HMAC-SHA512 variants
- Add support for Nettle 3.6.x and Nettle 3.7.x
- Add support for GC256B and GC512A ECC curves 
- Add support for SHA3 256 SHAKE
- Add support for ARCTWO (RC2)
  
### Fixed
- P-512 curve was missing on internal curves table with cdata


## [1.5] - 2020-04-01
### Fixed
- Fix RSA to do right calculation of exponent lengths

### Added
- Binding to time resistant RSA decrypt
- Binding to time and side-channel resistant RSA decrypt


## [1.4] - 2020-03-28
### Fixed
- Fix (again) RSA to do right calculation of signature length


## [1.3] - 2020-03-27
### Fixed
- Fix RSA to pass the right known length to mpz.tostring() on signing

### Changed
- No need to give length to ecc scalar:d()


## [1.2] - 2020-03-26
### Added
- Support for `pbkdf2.hmac_gosthash94cp`

### Fixed
- ecc point returned invalid length on some curves for point:x(),
  point.y(), point.xy() and point.coordinates()


## [1.1] - 2019-11-29
### Fixed
- Random data used with OpenResty leaked a callback which could have
  resulted `too many callbacks` error. The function is now casted as
  a proper C function.


## [1.0] - 2019-10-28
### Everything
- Huge refactoring. A lot of new stuff. From this on, I will keep better changelog, ;-).


## [0.105] - 2017-09-29
### Fixed
- Hogweed library loading (copy paste bug, sorry).


## [0.104] - 2017-09-28
### Added
- Option to override library paths with global variables
  (see [#15](https://github.com/bungle/lua-resty-nettle/pull/15),
     thanks [@shashiranjan84](https://github.com/shashiranjan84))


## [0.103] - 2017-08-12
### Fixed
- More robust library loaders (they sometimes returned non-helpful booleans)
  (see [#14](https://github.com/bungle/lua-resty-nettle/issues/14),
     thanks [@xiangnanscu](https://github.com/xiangnanscu))


## [0.102] - 2017-06-05
### Fixed
- Prefixed Nettle structs to avoid naming conflicts with other
  libraries such as OpenSSL
  (see [#13](https://github.com/bungle/lua-resty-nettle/issues/13),
   thanks [@xiangnanscu](https://github.com/xiangnanscu))


## [0.101] - 2017-06-05
### Changed
- Tries to load older dependencies in case the latest are not available
  (no gurantees that they will work, though)


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
