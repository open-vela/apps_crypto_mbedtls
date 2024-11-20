Introduce a level of indirection and versioning in the config files
-------------------------------------------------------------------

`config.h` was split into `build_info.h` and `mbedtls_config.h`.
`build_info.h` is intended to be included from C code directly, while
`mbedtls_config.h` is intended to be edited by end users wishing to
change the build configuration, and should generally only be included from
`build_info.h`. This is because all the preprocessor logic has been moved
into `build_info.h`, including the handling of the `MBEDTLS_CONFIG_FILE`
macro.

A config file version symbol, `MBEDTLS_CONFIG_VERSION` was introduced.
Defining it to a particular value will ensure that mbedtls interprets
the config file in a way that's compatible with the config file format
used by the mbedtls release whose `MBEDTLS_VERSION_NUMBER` has the same
value.
The only value supported by mbedtls 3.0.0 is `0x03000000`.
