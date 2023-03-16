/**
 * This file is intended to be used to build PSA test driver libraries. It is
 * intended to be appended by the test build system to the crypto_config.h file
 * of the Mbed TLS library the test library will be linked to. It mirrors the
 * PSA_ACCEL_* macros defining the cryptographic operations the test library
 * supports.
 */

#if defined(PSA_WANT_ALG_CBC_NO_PADDING)
#if defined(MBEDTLS_PSA_ACCEL_ALG_CBC_NO_PADDING)
#undef MBEDTLS_PSA_ACCEL_ALG_CBC_NO_PADDING
#else
#define MBEDTLS_PSA_ACCEL_ALG_CBC_NO_PADDING 1
#endif
#endif

#if defined(PSA_WANT_ALG_CBC_PKCS7)
#if defined(MBEDTLS_PSA_ACCEL_ALG_CBC_PKCS7)
#undef MBEDTLS_PSA_ACCEL_ALG_CBC_PKCS7
#else
#define MBEDTLS_PSA_ACCEL_ALG_CBC_PKCS7 1
#endif
#endif

#if defined(PSA_WANT_ALG_CFB)
#if defined(MBEDTLS_PSA_ACCEL_ALG_CFB)
#undef MBEDTLS_PSA_ACCEL_ALG_CFB
#else
#define MBEDTLS_PSA_ACCEL_ALG_CFB 1
#endif
#endif

#if defined(PSA_WANT_ALG_CTR)
#if defined(MBEDTLS_PSA_ACCEL_ALG_CTR)
#undef MBEDTLS_PSA_ACCEL_ALG_CTR
#else
#define MBEDTLS_PSA_ACCEL_ALG_CTR 1
#endif
#endif

#if defined(PSA_WANT_ALG_DETERMINISTIC_ECDSA)
#if defined(MBEDTLS_PSA_ACCEL_ALG_DETERMINISTIC_ECDSA)
#undef MBEDTLS_PSA_ACCEL_ALG_DETERMINISTIC_ECDSA
#else
#define MBEDTLS_PSA_ACCEL_ALG_DETERMINISTIC_ECDSA 1
#endif
#endif

#if defined(PSA_WANT_ALG_ECDSA)
#if defined(MBEDTLS_PSA_ACCEL_ALG_ECDSA)
#undef MBEDTLS_PSA_ACCEL_ALG_ECDSA
#else
#define MBEDTLS_PSA_ACCEL_ALG_ECDSA 1
#endif
#endif

#if defined(PSA_WANT_ALG_ECDH)
#if defined(MBEDTLS_PSA_ACCEL_ALG_ECDH)
#undef MBEDTLS_PSA_ACCEL_ALG_ECDH
#else
#define MBEDTLS_PSA_ACCEL_ALG_ECDH 1
#endif
#endif

#if defined(PSA_WANT_ALG_MD5)
#if defined(MBEDTLS_PSA_ACCEL_ALG_MD5)
#undef MBEDTLS_PSA_ACCEL_ALG_MD5
#else
#define MBEDTLS_PSA_ACCEL_ALG_MD5 1
#endif
#endif

#if defined(PSA_WANT_ALG_OFB)
#if defined(MBEDTLS_PSA_ACCEL_ALG_OFB)
#undef MBEDTLS_PSA_ACCEL_ALG_OFB
#else
#define MBEDTLS_PSA_ACCEL_ALG_OFB 1
#endif
#endif

#if defined(PSA_WANT_ALG_RIPEMD160)
#if defined(MBEDTLS_PSA_ACCEL_ALG_RIPEMD160)
#undef MBEDTLS_PSA_ACCEL_ALG_RIPEMD160
#else
#define MBEDTLS_PSA_ACCEL_ALG_RIPEMD160 1
#endif
#endif

#if defined(PSA_WANT_ALG_RSA_PKCS1V15_SIGN)
#if defined(MBEDTLS_PSA_ACCEL_ALG_RSA_PKCS1V15_SIGN)
#undef MBEDTLS_PSA_ACCEL_ALG_RSA_PKCS1V15_SIGN
#else
#define MBEDTLS_PSA_ACCEL_ALG_RSA_PKCS1V15_SIGN 1
#endif
#endif

#if defined(PSA_WANT_ALG_RSA_PSS)
#if defined(MBEDTLS_PSA_ACCEL_ALG_RSA_PSS)
#undef MBEDTLS_PSA_ACCEL_ALG_RSA_PSS
#else
#define MBEDTLS_PSA_ACCEL_ALG_RSA_PSS 1
#endif
#endif

#if defined(PSA_WANT_ALG_SHA_1)
#if defined(MBEDTLS_PSA_ACCEL_ALG_SHA_1)
#undef MBEDTLS_PSA_ACCEL_ALG_SHA_1
#else
#define MBEDTLS_PSA_ACCEL_ALG_SHA_1 1
#endif
#endif

#if defined(PSA_WANT_ALG_SHA_224)
#if defined(MBEDTLS_PSA_ACCEL_ALG_SHA_224)
#undef MBEDTLS_PSA_ACCEL_ALG_SHA_224
#else
#define MBEDTLS_PSA_ACCEL_ALG_SHA_224 1
#endif
#endif

#if defined(PSA_WANT_ALG_SHA_256)
#if defined(MBEDTLS_PSA_ACCEL_ALG_SHA_256)
#undef MBEDTLS_PSA_ACCEL_ALG_SHA_256
#else
#define MBEDTLS_PSA_ACCEL_ALG_SHA_256 1
#endif
#endif

#if defined(PSA_WANT_ALG_SHA_384)
#if defined(MBEDTLS_PSA_ACCEL_ALG_SHA_384)
#undef MBEDTLS_PSA_ACCEL_ALG_SHA_384
#else
#define MBEDTLS_PSA_ACCEL_ALG_SHA_384 1
#endif
#endif

#if defined(PSA_WANT_ALG_SHA_512)
#if defined(MBEDTLS_PSA_ACCEL_ALG_SHA_512)
#undef MBEDTLS_PSA_ACCEL_ALG_SHA_512
#else
#define MBEDTLS_PSA_ACCEL_ALG_SHA_512 1
#endif
#endif

#if defined(PSA_WANT_ALG_XTS)
#if defined(MBEDTLS_PSA_ACCEL_ALG_XTS)
#undef MBEDTLS_PSA_ACCEL_ALG_XTS
#else
#define MBEDTLS_PSA_ACCEL_ALG_XTS 1
#endif
#endif

#if defined(PSA_WANT_ALG_CHACHA20_POLY1305)
#if defined(MBEDTLS_PSA_ACCEL_ALG_CHACHA20_POLY1305)
#undef MBEDTLS_PSA_ACCEL_ALG_CHACHA20_POLY1305
#else
#define MBEDTLS_PSA_ACCEL_ALG_CHACHA20_POLY1305 1
#endif
#endif

#if defined(PSA_WANT_KEY_TYPE_AES)
#if defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_AES)
#undef MBEDTLS_PSA_ACCEL_KEY_TYPE_AES
#else
#define MBEDTLS_PSA_ACCEL_KEY_TYPE_AES 1
#endif
#endif

#if defined(PSA_WANT_KEY_TYPE_ARIA)
#if defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_ARIA)
#undef MBEDTLS_PSA_ACCEL_KEY_TYPE_ARIA
#else
#define MBEDTLS_PSA_ACCEL_KEY_TYPE_ARIA 1
#endif
#endif

#if defined(PSA_WANT_KEY_TYPE_CAMELLIA)
#if defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_CAMELLIA)
#undef MBEDTLS_PSA_ACCEL_KEY_TYPE_CAMELLIA
#else
#define MBEDTLS_PSA_ACCEL_KEY_TYPE_CAMELLIA 1
#endif
#endif

#if defined(PSA_WANT_KEY_TYPE_ECC_KEY_PAIR)
#if defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR)
#undef MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR
#else
#define MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR 1
#endif
#endif

#if defined(PSA_WANT_KEY_TYPE_RSA_KEY_PAIR)
#if defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_RSA_KEY_PAIR)
#undef MBEDTLS_PSA_ACCEL_KEY_TYPE_RSA_KEY_PAIR
#else
#define MBEDTLS_PSA_ACCEL_KEY_TYPE_RSA_KEY_PAIR 1
#endif
#endif

#if defined(PSA_WANT_KEY_TYPE_CHACHA20)
#if defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_CHACHA20)
#undef MBEDTLS_PSA_ACCEL_KEY_TYPE_CHACHA20
#else
#define MBEDTLS_PSA_ACCEL_KEY_TYPE_CHACHA20 1
#endif
#endif

#define MBEDTLS_PSA_ACCEL_ALG_CBC_MAC 1
#define MBEDTLS_PSA_ACCEL_ALG_CCM 1
#define MBEDTLS_PSA_ACCEL_ALG_CMAC 1
#define MBEDTLS_PSA_ACCEL_ALG_ECB_NO_PADDING 1
#define MBEDTLS_PSA_ACCEL_ALG_GCM 1
#define MBEDTLS_PSA_ACCEL_ALG_HKDF 1
#define MBEDTLS_PSA_ACCEL_ALG_HKDF_EXTRACT 1
#define MBEDTLS_PSA_ACCEL_ALG_HKDF_EXPAND 1
#define MBEDTLS_PSA_ACCEL_ALG_HMAC 1
#define MBEDTLS_PSA_ACCEL_ALG_RSA_OAEP 1
#define MBEDTLS_PSA_ACCEL_ALG_RSA_PKCS1V15_CRYPT 1
#define MBEDTLS_PSA_ACCEL_ALG_STREAM_CIPHER 1
#define MBEDTLS_PSA_ACCEL_ALG_TLS12_PRF 1
#define MBEDTLS_PSA_ACCEL_ALG_TLS12_PSK_TO_MS 1

#if defined(MBEDTLS_PSA_ACCEL_ALG_ECDSA)
#if defined(MBEDTLS_PSA_ACCEL_ALG_ECDH)
#define MBEDTLS_PSA_ACCEL_ECC_BRAINPOOL_P_R1_256 1
#define MBEDTLS_PSA_ACCEL_ECC_BRAINPOOL_P_R1_384 1
#define MBEDTLS_PSA_ACCEL_ECC_BRAINPOOL_P_R1_512 1
#define MBEDTLS_PSA_ACCEL_ECC_MONTGOMERY_255 1
#define MBEDTLS_PSA_ACCEL_ECC_MONTGOMERY_448 1
#define MBEDTLS_PSA_ACCEL_ECC_SECP_K1_192 1
#define MBEDTLS_PSA_ACCEL_ECC_SECP_K1_224 1
#define MBEDTLS_PSA_ACCEL_ECC_SECP_K1_256 1
#define MBEDTLS_PSA_ACCEL_ECC_SECP_R1_192 1
#define MBEDTLS_PSA_ACCEL_ECC_SECP_R1_224 1
#define MBEDTLS_PSA_ACCEL_ECC_SECP_R1_256 1
#define MBEDTLS_PSA_ACCEL_ECC_SECP_R1_384 1
#define MBEDTLS_PSA_ACCEL_ECC_SECP_R1_521 1
#endif
#endif

#define MBEDTLS_PSA_ACCEL_KEY_TYPE_DERIVE 1
#define MBEDTLS_PSA_ACCEL_KEY_TYPE_HMAC 1
#define MBEDTLS_PSA_ACCEL_KEY_TYPE_DES 1
#define MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_PUBLIC_KEY 1
#define MBEDTLS_PSA_ACCEL_KEY_TYPE_RAW_DATA 1
#define MBEDTLS_PSA_ACCEL_KEY_TYPE_RSA_PUBLIC_KEY 1
