/*
 *  PSA hashing layer on top of Mbed TLS software crypto
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include "common.h"

#if defined(MBEDTLS_PSA_CRYPTO_C)

#include <psa/crypto.h>
#include "psa_crypto_core.h"
#include "psa_crypto_hash.h"

#include <mbedtls/error.h>
#include <string.h>

/* Use builtin defines specific to this compilation unit, since the test driver
 * relies on the software driver. */
#if( defined(MBEDTLS_PSA_BUILTIN_ALG_MD2) || \
    ( defined(PSA_CRYPTO_DRIVER_TEST) && defined(MBEDTLS_PSA_ACCEL_ALG_MD2) ) )
#define BUILTIN_ALG_MD2         1
#endif
#if( defined(MBEDTLS_PSA_BUILTIN_ALG_MD4) || \
    ( defined(PSA_CRYPTO_DRIVER_TEST) && defined(MBEDTLS_PSA_ACCEL_ALG_MD4) ) )
#define BUILTIN_ALG_MD4         1
#endif
#if( defined(MBEDTLS_PSA_BUILTIN_ALG_MD5) || \
    ( defined(PSA_CRYPTO_DRIVER_TEST) && defined(MBEDTLS_PSA_ACCEL_ALG_MD5) ) )
#define BUILTIN_ALG_MD5         1
#endif
#if( defined(MBEDTLS_PSA_BUILTIN_ALG_RIPEMD160) || \
    ( defined(PSA_CRYPTO_DRIVER_TEST) && defined(MBEDTLS_PSA_ACCEL_ALG_RIPEMD160) ) )
#define BUILTIN_ALG_RIPEMD160   1
#endif
#if( defined(MBEDTLS_PSA_BUILTIN_ALG_SHA_1) || \
    ( defined(PSA_CRYPTO_DRIVER_TEST) && defined(MBEDTLS_PSA_ACCEL_ALG_SHA_1) ) )
#define BUILTIN_ALG_SHA_1       1
#endif
#if( defined(MBEDTLS_PSA_BUILTIN_ALG_SHA_224) || \
    ( defined(PSA_CRYPTO_DRIVER_TEST) && defined(MBEDTLS_PSA_ACCEL_ALG_SHA_224) ) )
#define BUILTIN_ALG_SHA_224     1
#endif
#if( defined(MBEDTLS_PSA_BUILTIN_ALG_SHA_256) || \
    ( defined(PSA_CRYPTO_DRIVER_TEST) && defined(MBEDTLS_PSA_ACCEL_ALG_SHA_256) ) )
#define BUILTIN_ALG_SHA_256     1
#endif
#if( defined(MBEDTLS_PSA_BUILTIN_ALG_SHA_384) || \
    ( defined(PSA_CRYPTO_DRIVER_TEST) && defined(MBEDTLS_PSA_ACCEL_ALG_SHA_384) ) )
#define BUILTIN_ALG_SHA_384     1
#endif
#if( defined(MBEDTLS_PSA_BUILTIN_ALG_SHA_512) || \
    ( defined(PSA_CRYPTO_DRIVER_TEST) && defined(MBEDTLS_PSA_ACCEL_ALG_SHA_512) ) )
#define BUILTIN_ALG_SHA_512     1
#endif

#if ( defined(BUILTIN_ALG_MD2) && !defined(MBEDTLS_PSA_ACCEL_ALG_MD2) ) || \
    ( defined(BUILTIN_ALG_MD4) && !defined(MBEDTLS_PSA_ACCEL_ALG_MD4) ) || \
    ( defined(BUILTIN_ALG_MD5) && !defined(MBEDTLS_PSA_ACCEL_ALG_MD5) ) || \
    ( defined(BUILTIN_ALG_RIPEMD160) && !defined(MBEDTLS_PSA_ACCEL_ALG_RIPEMD160) ) || \
    ( defined(BUILTIN_ALG_SHA_1) && !defined(MBEDTLS_PSA_ACCEL_ALG_SHA_1) ) || \
    ( defined(BUILTIN_ALG_SHA_224) && !defined(MBEDTLS_PSA_ACCEL_ALG_SHA_224) ) || \
    ( defined(BUILTIN_ALG_SHA_256) && !defined(MBEDTLS_PSA_ACCEL_ALG_SHA_256) ) || \
    ( defined(BUILTIN_ALG_SHA_384) && !defined(MBEDTLS_PSA_ACCEL_ALG_SHA_384) ) || \
    ( defined(BUILTIN_ALG_SHA_512) && !defined(MBEDTLS_PSA_ACCEL_ALG_SHA_512) )
#define INCLUDE_HASH_MBEDTLS_DRIVER    1
#endif

#if defined(PSA_CRYPTO_DRIVER_TEST) && \
    ( defined(MBEDTLS_PSA_ACCEL_ALG_MD2) || \
      defined(MBEDTLS_PSA_ACCEL_ALG_MD4) || \
      defined(MBEDTLS_PSA_ACCEL_ALG_MD5) || \
      defined(MBEDTLS_PSA_ACCEL_ALG_RIPEMD160) || \
      defined(MBEDTLS_PSA_ACCEL_ALG_SHA_1) || \
      defined(MBEDTLS_PSA_ACCEL_ALG_SHA_224) || \
      defined(MBEDTLS_PSA_ACCEL_ALG_SHA_256) || \
      defined(MBEDTLS_PSA_ACCEL_ALG_SHA_384) || \
      defined(MBEDTLS_PSA_ACCEL_ALG_SHA_512) )
#define INCLUDE_HASH_TEST_DRIVER
#endif

#if defined(INCLUDE_HASH_MBEDTLS_DRIVER) || \
    defined(INCLUDE_HASH_TEST_DRIVER)
#define INCLUDE_HASH_CORE       1
#endif

/* Implement the PSA driver hash interface on top of mbed TLS if either the
 * software driver or the test driver requires it. */
#if defined(INCLUDE_HASH_CORE)
static psa_status_t hash_abort(
    mbedtls_psa_hash_operation_t *operation )
{
    switch( operation->alg )
    {
        case 0:
            /* The object has (apparently) been initialized but it is not
             * in use. It's ok to call abort on such an object, and there's
             * nothing to do. */
            break;
#if defined(BUILTIN_ALG_MD2)
        case PSA_ALG_MD2:
            mbedtls_md2_free( &operation->ctx.md2 );
            break;
#endif
#if defined(BUILTIN_ALG_MD4)
        case PSA_ALG_MD4:
            mbedtls_md4_free( &operation->ctx.md4 );
            break;
#endif
#if defined(BUILTIN_ALG_MD5)
        case PSA_ALG_MD5:
            mbedtls_md5_free( &operation->ctx.md5 );
            break;
#endif
#if defined(BUILTIN_ALG_RIPEMD160)
        case PSA_ALG_RIPEMD160:
            mbedtls_ripemd160_free( &operation->ctx.ripemd160 );
            break;
#endif
#if defined(BUILTIN_ALG_SHA_1)
        case PSA_ALG_SHA_1:
            mbedtls_sha1_free( &operation->ctx.sha1 );
            break;
#endif
#if defined(BUILTIN_ALG_SHA_224)
        case PSA_ALG_SHA_224:
            mbedtls_sha256_free( &operation->ctx.sha256 );
            break;
#endif
#if defined(BUILTIN_ALG_SHA_256)
        case PSA_ALG_SHA_256:
            mbedtls_sha256_free( &operation->ctx.sha256 );
            break;
#endif
#if defined(BUILTIN_ALG_SHA_384)
        case PSA_ALG_SHA_384:
            mbedtls_sha512_free( &operation->ctx.sha512 );
            break;
#endif
#if defined(BUILTIN_ALG_SHA_512)
        case PSA_ALG_SHA_512:
            mbedtls_sha512_free( &operation->ctx.sha512 );
            break;
#endif
        default:
            return( PSA_ERROR_BAD_STATE );
    }
    operation->alg = 0;
    return( PSA_SUCCESS );
}

static psa_status_t hash_setup(
    mbedtls_psa_hash_operation_t *operation,
    psa_algorithm_t alg )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    /* A context must be freshly initialized before it can be set up. */
    if( operation->alg != 0 )
    {
        return( PSA_ERROR_BAD_STATE );
    }

    switch( alg )
    {
#if defined(BUILTIN_ALG_MD2)
        case PSA_ALG_MD2:
            mbedtls_md2_init( &operation->ctx.md2 );
            ret = mbedtls_md2_starts_ret( &operation->ctx.md2 );
            break;
#endif
#if defined(BUILTIN_ALG_MD4)
        case PSA_ALG_MD4:
            mbedtls_md4_init( &operation->ctx.md4 );
            ret = mbedtls_md4_starts_ret( &operation->ctx.md4 );
            break;
#endif
#if defined(BUILTIN_ALG_MD5)
        case PSA_ALG_MD5:
            mbedtls_md5_init( &operation->ctx.md5 );
            ret = mbedtls_md5_starts_ret( &operation->ctx.md5 );
            break;
#endif
#if defined(BUILTIN_ALG_RIPEMD160)
        case PSA_ALG_RIPEMD160:
            mbedtls_ripemd160_init( &operation->ctx.ripemd160 );
            ret = mbedtls_ripemd160_starts_ret( &operation->ctx.ripemd160 );
            break;
#endif
#if defined(BUILTIN_ALG_SHA_1)
        case PSA_ALG_SHA_1:
            mbedtls_sha1_init( &operation->ctx.sha1 );
            ret = mbedtls_sha1_starts_ret( &operation->ctx.sha1 );
            break;
#endif
#if defined(BUILTIN_ALG_SHA_224)
        case PSA_ALG_SHA_224:
            mbedtls_sha256_init( &operation->ctx.sha256 );
            ret = mbedtls_sha256_starts_ret( &operation->ctx.sha256, 1 );
            break;
#endif
#if defined(BUILTIN_ALG_SHA_256)
        case PSA_ALG_SHA_256:
            mbedtls_sha256_init( &operation->ctx.sha256 );
            ret = mbedtls_sha256_starts_ret( &operation->ctx.sha256, 0 );
            break;
#endif
#if defined(BUILTIN_ALG_SHA_384)
        case PSA_ALG_SHA_384:
            mbedtls_sha512_init( &operation->ctx.sha512 );
            ret = mbedtls_sha512_starts_ret( &operation->ctx.sha512, 1 );
            break;
#endif
#if defined(BUILTIN_ALG_SHA_512)
        case PSA_ALG_SHA_512:
            mbedtls_sha512_init( &operation->ctx.sha512 );
            ret = mbedtls_sha512_starts_ret( &operation->ctx.sha512, 0 );
            break;
#endif
        default:
            return( PSA_ALG_IS_HASH( alg ) ?
                    PSA_ERROR_NOT_SUPPORTED :
                    PSA_ERROR_INVALID_ARGUMENT );
    }
    if( ret == 0 )
        operation->alg = alg;
    else
        hash_abort( operation );
    return( mbedtls_to_psa_error( ret ) );
}

static psa_status_t hash_clone(
    const mbedtls_psa_hash_operation_t *source_operation,
    mbedtls_psa_hash_operation_t *target_operation )
{
    switch( source_operation->alg )
    {
        case 0:
            return( PSA_ERROR_BAD_STATE );
#if defined(BUILTIN_ALG_MD2)
        case PSA_ALG_MD2:
            mbedtls_md2_clone( &target_operation->ctx.md2,
                               &source_operation->ctx.md2 );
            break;
#endif
#if defined(BUILTIN_ALG_MD4)
        case PSA_ALG_MD4:
            mbedtls_md4_clone( &target_operation->ctx.md4,
                               &source_operation->ctx.md4 );
            break;
#endif
#if defined(BUILTIN_ALG_MD5)
        case PSA_ALG_MD5:
            mbedtls_md5_clone( &target_operation->ctx.md5,
                               &source_operation->ctx.md5 );
            break;
#endif
#if defined(BUILTIN_ALG_RIPEMD160)
        case PSA_ALG_RIPEMD160:
            mbedtls_ripemd160_clone( &target_operation->ctx.ripemd160,
                                     &source_operation->ctx.ripemd160 );
            break;
#endif
#if defined(BUILTIN_ALG_SHA_1)
        case PSA_ALG_SHA_1:
            mbedtls_sha1_clone( &target_operation->ctx.sha1,
                                &source_operation->ctx.sha1 );
            break;
#endif
#if defined(BUILTIN_ALG_SHA_224)
        case PSA_ALG_SHA_224:
            mbedtls_sha256_clone( &target_operation->ctx.sha256,
                                  &source_operation->ctx.sha256 );
            break;
#endif
#if defined(BUILTIN_ALG_SHA_256)
        case PSA_ALG_SHA_256:
            mbedtls_sha256_clone( &target_operation->ctx.sha256,
                                  &source_operation->ctx.sha256 );
            break;
#endif
#if defined(BUILTIN_ALG_SHA_384)
        case PSA_ALG_SHA_384:
            mbedtls_sha512_clone( &target_operation->ctx.sha512,
                                  &source_operation->ctx.sha512 );
            break;
#endif
#if defined(BUILTIN_ALG_SHA_512)
        case PSA_ALG_SHA_512:
            mbedtls_sha512_clone( &target_operation->ctx.sha512,
                                  &source_operation->ctx.sha512 );
            break;
#endif
        default:
            (void) source_operation;
            (void) target_operation;
            return( PSA_ERROR_NOT_SUPPORTED );
    }

    target_operation->alg = source_operation->alg;
    return( PSA_SUCCESS );
}

static psa_status_t hash_update(
    mbedtls_psa_hash_operation_t *operation,
    const uint8_t *input,
    size_t input_length )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    switch( operation->alg )
    {
#if defined(BUILTIN_ALG_MD2)
        case PSA_ALG_MD2:
            ret = mbedtls_md2_update_ret( &operation->ctx.md2,
                                          input, input_length );
            break;
#endif
#if defined(BUILTIN_ALG_MD4)
        case PSA_ALG_MD4:
            ret = mbedtls_md4_update_ret( &operation->ctx.md4,
                                          input, input_length );
            break;
#endif
#if defined(BUILTIN_ALG_MD5)
        case PSA_ALG_MD5:
            ret = mbedtls_md5_update_ret( &operation->ctx.md5,
                                          input, input_length );
            break;
#endif
#if defined(BUILTIN_ALG_RIPEMD160)
        case PSA_ALG_RIPEMD160:
            ret = mbedtls_ripemd160_update_ret( &operation->ctx.ripemd160,
                                                input, input_length );
            break;
#endif
#if defined(BUILTIN_ALG_SHA_1)
        case PSA_ALG_SHA_1:
            ret = mbedtls_sha1_update_ret( &operation->ctx.sha1,
                                           input, input_length );
            break;
#endif
#if defined(BUILTIN_ALG_SHA_224)
        case PSA_ALG_SHA_224:
            ret = mbedtls_sha256_update_ret( &operation->ctx.sha256,
                                             input, input_length );
            break;
#endif
#if defined(BUILTIN_ALG_SHA_256)
        case PSA_ALG_SHA_256:
            ret = mbedtls_sha256_update_ret( &operation->ctx.sha256,
                                             input, input_length );
            break;
#endif
#if defined(BUILTIN_ALG_SHA_384)
        case PSA_ALG_SHA_384:
            ret = mbedtls_sha512_update_ret( &operation->ctx.sha512,
                                             input, input_length );
            break;
#endif
#if defined(BUILTIN_ALG_SHA_512)
        case PSA_ALG_SHA_512:
            ret = mbedtls_sha512_update_ret( &operation->ctx.sha512,
                                             input, input_length );
            break;
#endif
        default:
            (void) input;
            (void) input_length;
            return( PSA_ERROR_BAD_STATE );
    }

    if( ret != 0 )
        hash_abort( operation );
    return( mbedtls_to_psa_error( ret ) );
}

static psa_status_t hash_finish(
    mbedtls_psa_hash_operation_t *operation,
    uint8_t *hash,
    size_t hash_size,
    size_t *hash_length )
{
    psa_status_t status;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t actual_hash_length = PSA_HASH_LENGTH( operation->alg );

    /* Fill the output buffer with something that isn't a valid hash
     * (barring an attack on the hash and deliberately-crafted input),
     * in case the caller doesn't check the return status properly. */
    *hash_length = hash_size;
    /* If hash_size is 0 then hash may be NULL and then the
     * call to memset would have undefined behavior. */
    if( hash_size != 0 )
        memset( hash, '!', hash_size );

    if( hash_size < actual_hash_length )
    {
        status = PSA_ERROR_BUFFER_TOO_SMALL;
        goto exit;
    }

    switch( operation->alg )
    {
#if defined(BUILTIN_ALG_MD2)
        case PSA_ALG_MD2:
            ret = mbedtls_md2_finish_ret( &operation->ctx.md2, hash );
            break;
#endif
#if defined(BUILTIN_ALG_MD4)
        case PSA_ALG_MD4:
            ret = mbedtls_md4_finish_ret( &operation->ctx.md4, hash );
            break;
#endif
#if defined(BUILTIN_ALG_MD5)
        case PSA_ALG_MD5:
            ret = mbedtls_md5_finish_ret( &operation->ctx.md5, hash );
            break;
#endif
#if defined(BUILTIN_ALG_RIPEMD160)
        case PSA_ALG_RIPEMD160:
            ret = mbedtls_ripemd160_finish_ret( &operation->ctx.ripemd160, hash );
            break;
#endif
#if defined(BUILTIN_ALG_SHA_1)
        case PSA_ALG_SHA_1:
            ret = mbedtls_sha1_finish_ret( &operation->ctx.sha1, hash );
            break;
#endif
#if defined(BUILTIN_ALG_SHA_224)
        case PSA_ALG_SHA_224:
            ret = mbedtls_sha256_finish_ret( &operation->ctx.sha256, hash );
            break;
#endif
#if defined(BUILTIN_ALG_SHA_256)
        case PSA_ALG_SHA_256:
            ret = mbedtls_sha256_finish_ret( &operation->ctx.sha256, hash );
            break;
#endif
#if defined(BUILTIN_ALG_SHA_384)
        case PSA_ALG_SHA_384:
            ret = mbedtls_sha512_finish_ret( &operation->ctx.sha512, hash );
            break;
#endif
#if defined(BUILTIN_ALG_SHA_512)
        case PSA_ALG_SHA_512:
            ret = mbedtls_sha512_finish_ret( &operation->ctx.sha512, hash );
            break;
#endif
        default:
            (void) hash;
            return( PSA_ERROR_BAD_STATE );
    }
    status = mbedtls_to_psa_error( ret );

exit:
    if( status == PSA_SUCCESS )
    {
        *hash_length = actual_hash_length;
        return( hash_abort( operation ) );
    }
    else
    {
        hash_abort( operation );
        return( status );
    }
}

static psa_status_t hash_compute(
    psa_algorithm_t alg,
    const uint8_t *input,
    size_t input_length,
    uint8_t *hash,
    size_t hash_size,
    size_t *hash_length)
{
    mbedtls_psa_hash_operation_t operation = MBEDTLS_PSA_HASH_OPERATION_INIT;
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    *hash_length = hash_size;
    status = hash_setup( &operation, alg );
    if( status != PSA_SUCCESS )
        goto exit;
    status = hash_update( &operation, input, input_length );
    if( status != PSA_SUCCESS )
        goto exit;
    status = hash_finish( &operation, hash, hash_size, hash_length );
    if( status != PSA_SUCCESS )
        goto exit;

exit:
    if( status == PSA_SUCCESS )
        status = hash_abort( &operation );
    else
        hash_abort( &operation );
    return( status );
}
#endif /* INCLUDE_HASH_CORE */

#if defined(INCLUDE_HASH_MBEDTLS_DRIVER)
psa_status_t mbedtls_psa_hash_compute(
    psa_algorithm_t alg,
    const uint8_t *input,
    size_t input_length,
    uint8_t *hash,
    size_t hash_size,
    size_t *hash_length)
{
    return( hash_compute( alg, input, input_length,
                          hash, hash_size, hash_length ) );
}

psa_status_t mbedtls_psa_hash_setup(
    mbedtls_psa_hash_operation_t *operation,
    psa_algorithm_t alg )
{
    return( hash_setup( operation, alg ) );
}

psa_status_t mbedtls_psa_hash_clone(
    const mbedtls_psa_hash_operation_t *source_operation,
    mbedtls_psa_hash_operation_t *target_operation )
{
    return( hash_clone( source_operation, target_operation ) );
}

psa_status_t mbedtls_psa_hash_update(
    mbedtls_psa_hash_operation_t *operation,
    const uint8_t *input,
    size_t input_length )
{
    return( hash_update( operation, input, input_length ) );
}

psa_status_t mbedtls_psa_hash_finish(
    mbedtls_psa_hash_operation_t *operation,
    uint8_t *hash,
    size_t hash_size,
    size_t *hash_length )
{
    return( hash_finish( operation, hash, hash_size, hash_length ) );
}

psa_status_t mbedtls_psa_hash_abort(
    mbedtls_psa_hash_operation_t *operation )
{
    return( hash_abort( operation ) );
}
#endif /* INCLUDE_HASH_MBEDTLS_DRIVER */

 /*
  * BEYOND THIS POINT, TEST DRIVER ENTRY POINTS ONLY.
  */
#if defined(PSA_CRYPTO_DRIVER_TEST)

#if defined(INCLUDE_HASH_TEST_DRIVER)
psa_status_t is_hash_accelerated( psa_algorithm_t alg )
{
    switch( alg )
    {
#if defined(MBEDTLS_PSA_ACCEL_ALG_MD2)
        case PSA_ALG_MD2:
            return( PSA_SUCCESS );
#endif
#if defined(MBEDTLS_PSA_ACCEL_ALG_MD4)
        case PSA_ALG_MD4:
            return( PSA_SUCCESS );
#endif
#if defined(MBEDTLS_PSA_ACCEL_ALG_MD5)
        case PSA_ALG_MD5:
            return( PSA_SUCCESS );
#endif
#if defined(MBEDTLS_PSA_ACCEL_ALG_RIPEMD160)
        case PSA_ALG_RIPEMD160:
            return( PSA_SUCCESS );
#endif
#if defined(MBEDTLS_PSA_ACCEL_ALG_SHA_1)
        case PSA_ALG_SHA_1:
            return( PSA_SUCCESS );
#endif
#if defined(MBEDTLS_PSA_ACCEL_ALG_SHA_224)
        case PSA_ALG_SHA_224:
            return( PSA_SUCCESS );
#endif
#if defined(MBEDTLS_PSA_ACCEL_ALG_SHA_256)
        case PSA_ALG_SHA_256:
            return( PSA_SUCCESS );
#endif
#if defined(MBEDTLS_PSA_ACCEL_ALG_SHA_384)
        case PSA_ALG_SHA_384:
            return( PSA_SUCCESS );
#endif
#if defined(MBEDTLS_PSA_ACCEL_ALG_SHA_512)
        case PSA_ALG_SHA_512:
            return( PSA_SUCCESS );
#endif
        default:
            return( PSA_ERROR_NOT_SUPPORTED );
    }
}
#endif /* INCLUDE_HASH_TEST_DRIVER */

psa_status_t mbedtls_transparent_test_driver_hash_compute(
    psa_algorithm_t alg,
    const uint8_t *input,
    size_t input_length,
    uint8_t *hash,
    size_t hash_size,
    size_t *hash_length)
{
#if defined(INCLUDE_HASH_TEST_DRIVER)
    if( is_hash_accelerated( alg ) == PSA_SUCCESS )
        return( hash_compute( alg, input, input_length,
                              hash, hash_size, hash_length ) );
    else
        return( PSA_ERROR_NOT_SUPPORTED );
#else
    (void) alg;
    (void) input;
    (void) input_length;
    (void) hash;
    (void) hash_size;
    (void) hash_length;
    return( PSA_ERROR_NOT_SUPPORTED );
#endif
}

psa_status_t mbedtls_transparent_test_driver_hash_setup(
    mbedtls_transparent_test_driver_hash_operation_t *operation,
    psa_algorithm_t alg )
{
#if defined(INCLUDE_HASH_TEST_DRIVER)
    if( is_hash_accelerated( alg ) == PSA_SUCCESS )
        return( hash_setup( &operation->operation, alg ) );
    else
        return( PSA_ERROR_NOT_SUPPORTED );
#else
    (void) alg;
    (void) operation;
    return( PSA_ERROR_NOT_SUPPORTED );
#endif
}

psa_status_t mbedtls_transparent_test_driver_hash_clone(
    const mbedtls_transparent_test_driver_hash_operation_t *source_operation,
    mbedtls_transparent_test_driver_hash_operation_t *target_operation )
{
#if defined(INCLUDE_HASH_TEST_DRIVER)
    if( is_hash_accelerated( source_operation->operation.alg ) == PSA_SUCCESS )
        return( hash_clone( &source_operation->operation,
                            &target_operation->operation ) );
    else
        return( PSA_ERROR_BAD_STATE );
#else
    (void) source_operation;
    (void) target_operation;
    return( PSA_ERROR_NOT_SUPPORTED );
#endif
}

psa_status_t mbedtls_transparent_test_driver_hash_update(
    mbedtls_transparent_test_driver_hash_operation_t *operation,
    const uint8_t *input,
    size_t input_length )
{
#if defined(INCLUDE_HASH_TEST_DRIVER)
    if( is_hash_accelerated( operation->operation.alg ) == PSA_SUCCESS )
        return( hash_update( &operation->operation,
                             input, input_length ) );
    else
        return( PSA_ERROR_BAD_STATE );
#else
    (void) operation;
    (void) input;
    (void) input_length;
    return( PSA_ERROR_NOT_SUPPORTED );
#endif
}

psa_status_t mbedtls_transparent_test_driver_hash_finish(
    mbedtls_transparent_test_driver_hash_operation_t *operation,
    uint8_t *hash,
    size_t hash_size,
    size_t *hash_length )
{
#if defined(INCLUDE_HASH_TEST_DRIVER)
    if( is_hash_accelerated( operation->operation.alg ) == PSA_SUCCESS )
        return( hash_finish( &operation->operation,
                             hash, hash_size, hash_length ) );
    else
        return( PSA_ERROR_BAD_STATE );
#else
    (void) operation;
    (void) hash;
    (void) hash_size;
    (void) hash_length;
    return( PSA_ERROR_NOT_SUPPORTED );
#endif
}

psa_status_t mbedtls_transparent_test_driver_hash_abort(
    mbedtls_transparent_test_driver_hash_operation_t *operation )
{
#if defined(INCLUDE_HASH_TEST_DRIVER)
    return( hash_abort( &operation->operation ) );
#else
    (void) operation;
    return( PSA_ERROR_NOT_SUPPORTED );
#endif
}

#endif /* PSA_CRYPTO_DRIVER_TEST */

#endif /* MBEDTLS_PSA_CRYPTO_C */
