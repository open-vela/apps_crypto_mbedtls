/*
 *  PSA AEAD entry points
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

#include "psa_crypto_aead.h"
#include "psa_crypto_core.h"

#include <string.h>
#include "mbedtls/platform.h"
#if !defined(MBEDTLS_PLATFORM_C)
#define mbedtls_calloc calloc
#define mbedtls_free   free
#endif

#include "mbedtls/ccm.h"
#include "mbedtls/chachapoly.h"
#include "mbedtls/cipher.h"
#include "mbedtls/gcm.h"
#include "mbedtls/error.h"

/* Constant-time buffer comparison. This is duplication of code from
 * psa_crypto.c, but has nowhere private I can put it for the minute. Really
   belongs in the constant time module, when that gets implemented */
static inline int safer_memcmp( const uint8_t *a, const uint8_t *b, size_t n )
{
    size_t i;
    unsigned char diff = 0;

    for( i = 0; i < n; i++ )
        diff |= a[i] ^ b[i];

    return( diff );
}


static psa_status_t psa_aead_setup(
    psa_aead_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    psa_algorithm_t alg )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    size_t key_bits;
    const mbedtls_cipher_info_t *cipher_info;
    mbedtls_cipher_id_t cipher_id;
    size_t full_tag_length = 0;

    if( operation->key_set || operation->nonce_set ||
        operation->ad_started || operation->body_started )
    {
        return( PSA_ERROR_BAD_STATE );
    }

    key_bits = attributes->core.bits;

    cipher_info = mbedtls_cipher_info_from_psa( alg,
                                                attributes->core.type, key_bits,
                                                &cipher_id );
    if( cipher_info == NULL )
        return( PSA_ERROR_NOT_SUPPORTED );

    switch( PSA_ALG_AEAD_WITH_SHORTENED_TAG( alg, 0 ) )
    {
#if defined(MBEDTLS_PSA_BUILTIN_ALG_CCM)
        case PSA_ALG_AEAD_WITH_SHORTENED_TAG( PSA_ALG_CCM, 0 ):
            operation->alg = PSA_ALG_CCM;
            full_tag_length = 16;
            /* CCM allows the following tag lengths: 4, 6, 8, 10, 12, 14, 16.
             * The call to mbedtls_ccm_encrypt_and_tag or
             * mbedtls_ccm_auth_decrypt will validate the tag length. */
            if( PSA_BLOCK_CIPHER_BLOCK_LENGTH( attributes->core.type ) != 16 )
                return( PSA_ERROR_INVALID_ARGUMENT );

            mbedtls_ccm_init( &operation->ctx.ccm );
            status = mbedtls_to_psa_error(
                mbedtls_ccm_setkey( &operation->ctx.ccm, cipher_id,
                                    key_buffer, (unsigned int) key_bits ) );
            if( status != PSA_SUCCESS )
                return( status );
            break;
#endif /* MBEDTLS_PSA_BUILTIN_ALG_CCM */

#if defined(MBEDTLS_PSA_BUILTIN_ALG_GCM)
        case PSA_ALG_AEAD_WITH_SHORTENED_TAG( PSA_ALG_GCM, 0 ):
            operation->alg = PSA_ALG_GCM;
            full_tag_length = 16;
            /* GCM allows the following tag lengths: 4, 8, 12, 13, 14, 15, 16.
             * The call to mbedtls_gcm_crypt_and_tag or
             * mbedtls_gcm_auth_decrypt will validate the tag length. */
            if( PSA_BLOCK_CIPHER_BLOCK_LENGTH( attributes->core.type ) != 16 )
                return( PSA_ERROR_INVALID_ARGUMENT );

            mbedtls_gcm_init( &operation->ctx.gcm );
            status = mbedtls_to_psa_error(
                mbedtls_gcm_setkey( &operation->ctx.gcm, cipher_id,
                                    key_buffer, (unsigned int) key_bits ) );
            if( status != PSA_SUCCESS )
                return( status );
            break;
#endif /* MBEDTLS_PSA_BUILTIN_ALG_GCM */

#if defined(MBEDTLS_PSA_BUILTIN_ALG_CHACHA20_POLY1305)
        case PSA_ALG_AEAD_WITH_SHORTENED_TAG( PSA_ALG_CHACHA20_POLY1305, 0 ):
            operation->alg = PSA_ALG_CHACHA20_POLY1305;
            full_tag_length = 16;
            /* We only support the default tag length. */
            if( alg != PSA_ALG_CHACHA20_POLY1305 )
                return( PSA_ERROR_NOT_SUPPORTED );

            mbedtls_chachapoly_init( &operation->ctx.chachapoly );
            status = mbedtls_to_psa_error(
                mbedtls_chachapoly_setkey( &operation->ctx.chachapoly,
                                           key_buffer ) );
            if( status != PSA_SUCCESS )
                return( status );
            break;
#endif /* MBEDTLS_PSA_BUILTIN_ALG_CHACHA20_POLY1305 */

        default:
            return( PSA_ERROR_NOT_SUPPORTED );
    }

    if( PSA_AEAD_TAG_LENGTH( attributes->core.type,
                             key_bits, alg )
        > full_tag_length )
        return( PSA_ERROR_INVALID_ARGUMENT );

    operation->tag_length = PSA_AEAD_TAG_LENGTH( attributes->core.type,
                                                 key_bits,
                                                 alg );

    operation->key_set = 1;

    return( PSA_SUCCESS );
}

psa_status_t mbedtls_psa_aead_encrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *nonce, size_t nonce_length,
    const uint8_t *additional_data, size_t additional_data_length,
    const uint8_t *plaintext, size_t plaintext_length,
    uint8_t *ciphertext, size_t ciphertext_size, size_t *ciphertext_length )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_aead_operation_t operation = PSA_AEAD_OPERATION_INIT;
    uint8_t *tag;
    (void) key_buffer_size;

    status = psa_aead_setup( &operation, attributes, key_buffer, alg );
    if( status != PSA_SUCCESS )
        goto exit;

    /* For all currently supported modes, the tag is at the end of the
     * ciphertext. */
    if( ciphertext_size < ( plaintext_length + operation.tag_length ) )
    {
        status = PSA_ERROR_BUFFER_TOO_SMALL;
        goto exit;
    }
    tag = ciphertext + plaintext_length;

#if defined(MBEDTLS_PSA_BUILTIN_ALG_CCM)
    if( operation.alg == PSA_ALG_CCM )
    {
        status = mbedtls_to_psa_error(
            mbedtls_ccm_encrypt_and_tag( &operation.ctx.ccm,
                                         plaintext_length,
                                         nonce, nonce_length,
                                         additional_data,
                                         additional_data_length,
                                         plaintext, ciphertext,
                                         tag, operation.tag_length ) );
    }
    else
#endif /* MBEDTLS_PSA_BUILTIN_ALG_CCM */
#if defined(MBEDTLS_PSA_BUILTIN_ALG_GCM)
    if( operation.alg == PSA_ALG_GCM )
    {
        status = mbedtls_to_psa_error(
            mbedtls_gcm_crypt_and_tag( &operation.ctx.gcm,
                                       MBEDTLS_GCM_ENCRYPT,
                                       plaintext_length,
                                       nonce, nonce_length,
                                       additional_data, additional_data_length,
                                       plaintext, ciphertext,
                                       operation.tag_length, tag ) );
    }
    else
#endif /* MBEDTLS_PSA_BUILTIN_ALG_GCM */
#if defined(MBEDTLS_PSA_BUILTIN_ALG_CHACHA20_POLY1305)
    if( operation.alg == PSA_ALG_CHACHA20_POLY1305 )
    {
        if( nonce_length != 12 || operation.tag_length != 16 )
        {
            status = PSA_ERROR_NOT_SUPPORTED;
            goto exit;
        }
        status = mbedtls_to_psa_error(
            mbedtls_chachapoly_encrypt_and_tag( &operation.ctx.chachapoly,
                                                plaintext_length,
                                                nonce,
                                                additional_data,
                                                additional_data_length,
                                                plaintext,
                                                ciphertext,
                                                tag ) );
    }
    else
#endif /* MBEDTLS_PSA_BUILTIN_ALG_CHACHA20_POLY1305 */
    {
        (void) tag;
        return( PSA_ERROR_NOT_SUPPORTED );
    }

    if( status == PSA_SUCCESS )
        *ciphertext_length = plaintext_length + operation.tag_length;

exit:
    mbedtls_psa_aead_abort( &operation );

    return( status );
}

/* Locate the tag in a ciphertext buffer containing the encrypted data
 * followed by the tag. Return the length of the part preceding the tag in
 * *plaintext_length. This is the size of the plaintext in modes where
 * the encrypted data has the same size as the plaintext, such as
 * CCM and GCM. */
static psa_status_t psa_aead_unpadded_locate_tag( size_t tag_length,
                                                  const uint8_t *ciphertext,
                                                  size_t ciphertext_length,
                                                  size_t plaintext_size,
                                                  const uint8_t **p_tag )
{
    size_t payload_length;
    if( tag_length > ciphertext_length )
        return( PSA_ERROR_INVALID_ARGUMENT );
    payload_length = ciphertext_length - tag_length;
    if( payload_length > plaintext_size )
        return( PSA_ERROR_BUFFER_TOO_SMALL );
    *p_tag = ciphertext + payload_length;
    return( PSA_SUCCESS );
}

psa_status_t mbedtls_psa_aead_decrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *nonce, size_t nonce_length,
    const uint8_t *additional_data, size_t additional_data_length,
    const uint8_t *ciphertext, size_t ciphertext_length,
    uint8_t *plaintext, size_t plaintext_size, size_t *plaintext_length )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_aead_operation_t operation = PSA_AEAD_OPERATION_INIT;
    const uint8_t *tag = NULL;
    (void) key_buffer_size;

    status = psa_aead_setup( &operation, attributes, key_buffer, alg );
    if( status != PSA_SUCCESS )
        goto exit;

    status = psa_aead_unpadded_locate_tag( operation.tag_length,
                                           ciphertext, ciphertext_length,
                                           plaintext_size, &tag );
    if( status != PSA_SUCCESS )
        goto exit;

#if defined(MBEDTLS_PSA_BUILTIN_ALG_CCM)
    if( operation.alg == PSA_ALG_CCM )
    {
        status = mbedtls_to_psa_error(
            mbedtls_ccm_auth_decrypt( &operation.ctx.ccm,
                                      ciphertext_length - operation.tag_length,
                                      nonce, nonce_length,
                                      additional_data,
                                      additional_data_length,
                                      ciphertext, plaintext,
                                      tag, operation.tag_length ) );
    }
    else
#endif /* MBEDTLS_PSA_BUILTIN_ALG_CCM */
#if defined(MBEDTLS_PSA_BUILTIN_ALG_GCM)
    if( operation.alg == PSA_ALG_GCM )
    {
        status = mbedtls_to_psa_error(
            mbedtls_gcm_auth_decrypt( &operation.ctx.gcm,
                                      ciphertext_length - operation.tag_length,
                                      nonce, nonce_length,
                                      additional_data,
                                      additional_data_length,
                                      tag, operation.tag_length,
                                      ciphertext, plaintext ) );
    }
    else
#endif /* MBEDTLS_PSA_BUILTIN_ALG_GCM */
#if defined(MBEDTLS_PSA_BUILTIN_ALG_CHACHA20_POLY1305)
    if( operation.alg == PSA_ALG_CHACHA20_POLY1305 )
    {
        if( nonce_length != 12 || operation.tag_length != 16 )
        {
            status = PSA_ERROR_NOT_SUPPORTED;
            goto exit;
        }
        status = mbedtls_to_psa_error(
            mbedtls_chachapoly_auth_decrypt( &operation.ctx.chachapoly,
                                             ciphertext_length - operation.tag_length,
                                             nonce,
                                             additional_data,
                                             additional_data_length,
                                             tag,
                                             ciphertext,
                                             plaintext ) );
    }
    else
#endif /* MBEDTLS_PSA_BUILTIN_ALG_CHACHA20_POLY1305 */
    {
        return( PSA_ERROR_NOT_SUPPORTED );
    }

    if( status == PSA_SUCCESS )
        *plaintext_length = ciphertext_length - operation.tag_length;

exit:
    mbedtls_psa_aead_abort( &operation );

    if( status == PSA_SUCCESS )
        *plaintext_length = ciphertext_length - operation.tag_length;
    return( status );
}

/* Set the key and algorithm for a multipart authenticated encryption
 * operation. */
psa_status_t mbedtls_psa_aead_encrypt_setup( psa_aead_operation_t *operation,
                                             const psa_key_attributes_t *attributes,
                                             const uint8_t *key_buffer, size_t key_buffer_size,
                                             psa_algorithm_t alg )
{
    psa_status_t status;

    (void) key_buffer_size;

    status = psa_aead_setup( operation, attributes, key_buffer, alg );

    if( status == PSA_SUCCESS )
    {
        operation->is_encrypt = 1;
    }

    return ( status );
}

/* Set the key and algorithm for a multipart authenticated decryption
 * operation. */
psa_status_t mbedtls_psa_aead_decrypt_setup( psa_aead_operation_t *operation,
                                             const psa_key_attributes_t *attributes,
                                             const uint8_t *key_buffer, size_t key_buffer_size,
                                             psa_algorithm_t alg )
{
    psa_status_t status;

    (void) key_buffer_size;

    status = psa_aead_setup( operation, attributes, key_buffer, alg );

    if( status == PSA_SUCCESS )
    {
        operation->is_encrypt = 0;
    }

    return ( status );
}

/* Set a nonce for the multipart AEAD operation*/
psa_status_t mbedtls_psa_aead_set_nonce( psa_aead_operation_t *operation,
                                         const uint8_t *nonce,
                                         size_t nonce_length )
{
    psa_status_t status;

    #if defined(MBEDTLS_PSA_BUILTIN_ALG_GCM)
    if( operation->alg == PSA_ALG_GCM )
    {
        /* GCM sets nonce once additional data has been supplied */
        memcpy(operation->nonce, nonce, nonce_length);

        /* We know that nonce size cannot exceed the uint8_t size */
        operation->nonce_length = ( uint8_t ) nonce_length;
        status = PSA_SUCCESS;
    }
    else
#endif /* MBEDTLS_PSA_BUILTIN_ALG_GCM */
#if defined(MBEDTLS_PSA_BUILTIN_ALG_CCM)
    if( operation->alg == PSA_ALG_CCM )
    {
        /* Multipart CCM not supported as yet, so CCM is basically operating
           in oneshot mode. Store the nonce as we need this later */
        memcpy(operation->nonce, nonce, nonce_length);

        /* We know that nonce size cannot exceed the uint8_t size */
        operation->nonce_length = ( uint8_t ) nonce_length;
        status = PSA_SUCCESS;
    }
    else
#endif /* MBEDTLS_PSA_BUILTIN_ALG_CCM */
#if defined(MBEDTLS_PSA_BUILTIN_ALG_CHACHA20_POLY1305)
    if( operation->alg == PSA_ALG_CHACHA20_POLY1305 )
    {
        if( nonce_length != 12 && nonce_length != 8)
        {
            return( PSA_ERROR_INVALID_ARGUMENT );
        }

        status = mbedtls_to_psa_error(mbedtls_chachapoly_starts( &operation->ctx.chachapoly,
                                                                 nonce,
                                                                 operation->is_encrypt ?
                                                                 MBEDTLS_CHACHAPOLY_ENCRYPT :
                                                                 MBEDTLS_CHACHAPOLY_DECRYPT ) );
        }
    else
#endif /* MBEDTLS_PSA_BUILTIN_ALG_CHACHA20_POLY1305 */
    {
        ( void ) nonce;
        ( void ) nonce_length;

        return ( PSA_ERROR_NOT_SUPPORTED );
    }

    if( status == PSA_SUCCESS )
    {
        operation->nonce_set = 1;
    }

    return( status );
}
 /* Declare the lengths of the message and additional data for AEAD. */
psa_status_t mbedtls_psa_aead_set_lengths( psa_aead_operation_t *operation,
                                           size_t ad_length,
                                           size_t plaintext_length )
{

#if defined(MBEDTLS_PSA_BUILTIN_ALG_GCM)
    if( operation->alg == PSA_ALG_GCM )
    {
#if SIZE_MAX > UINT32_MAX
        if( ( (uint64_t) ad_length ) >> 61 != 0 ||
            ( (uint64_t) plaintext_length ) > 0xFFFFFFFE0ull )
        {
            return ( PSA_ERROR_INVALID_ARGUMENT );
        }
#endif
    }
    else
#endif /* MBEDTLS_PSA_BUILTIN_ALG_GCM */
#if defined(MBEDTLS_PSA_BUILTIN_ALG_CCM)
    if( operation->alg == PSA_ALG_CCM )
    {
        if( ad_length > 0xFF00 )
        {
            return ( PSA_ERROR_INVALID_ARGUMENT );
        }
    }
    else
#endif /* MBEDTLS_PSA_BUILTIN_ALG_CCM */
#if defined(MBEDTLS_PSA_BUILTIN_ALG_CHACHA20_POLY1305)
    if( operation->alg == PSA_ALG_CHACHA20_POLY1305 )
    {
        /* No length restrictions for ChaChaPoly. */
    }
    else
#endif /* MBEDTLS_PSA_BUILTIN_ALG_CHACHA20_POLY1305 */
    {
        ( void ) ad_length;
        ( void ) plaintext_length;

        return ( PSA_ERROR_NOT_SUPPORTED );
    }

    operation->ad_remaining = ad_length;
    operation->body_remaining = plaintext_length;
    operation->lengths_set = 1;

    return ( PSA_SUCCESS );
}

/* Pass additional data to an active multipart AEAD operation. */
psa_status_t mbedtls_psa_aead_update_ad( psa_aead_operation_t *operation,
                                         const uint8_t *input,
                                         size_t input_length )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    if( operation->lengths_set )
    {
        if ( operation->ad_remaining < input_length )
        {
            return( PSA_ERROR_INVALID_ARGUMENT );
        }

        operation->ad_remaining -= input_length;
    }

#if defined(MBEDTLS_PSA_BUILTIN_ALG_GCM)
    if( operation->alg == PSA_ALG_GCM )
    {
        if( !operation->lengths_set || operation->ad_started )
        {
            return( PSA_ERROR_BAD_STATE );
        }

        /* GCM currently requires all the additional data to be passed in in
         * one contigious buffer, so until that is re-done, we have to enforce
         * this, as we cannot allocate a buffer to collate multiple calls into.
           */
        if( input_length != operation->ad_remaining )
        {
            return ( PSA_ERROR_INVALID_ARGUMENT );
        }

        status = mbedtls_to_psa_error( mbedtls_gcm_starts( &operation->ctx.gcm,
                                                          operation->is_encrypt ?
                                                           MBEDTLS_GCM_ENCRYPT : MBEDTLS_GCM_DECRYPT,
                                                          operation->nonce,
                                                          operation->nonce_length,
                                                          input,
                                                          input_length ) );

    }
    else
#endif /* MBEDTLS_PSA_BUILTIN_ALG_GCM */
#if defined(MBEDTLS_PSA_BUILTIN_ALG_CCM)
    if( operation->alg == PSA_ALG_CCM )
    {
        /* CCM requires all additional data to be passed in in one go at the
           minute, as we are basically operating in oneshot mode. */
        if( !operation->lengths_set || operation->ad_started )
        {
            return( PSA_ERROR_BAD_STATE );
        }

        /* Save the additional data for later, this will be passed in
           when we have the body. */
        operation->ad_buffer = ( uint8_t * ) mbedtls_calloc(1, input_length );

        if( operation->ad_buffer )
        {
            memcpy( operation->ad_buffer, input, input_length );
            operation->ad_length = input_length;
        }
        else
        {
            return ( PSA_ERROR_INSUFFICIENT_MEMORY );
        }
    }
    else
#endif /* MBEDTLS_PSA_BUILTIN_ALG_CCM */
#if defined(MBEDTLS_PSA_BUILTIN_ALG_CHACHA20_POLY1305)
    if( operation->alg == PSA_ALG_CHACHA20_POLY1305 )
    {
        status = mbedtls_to_psa_error( mbedtls_chachapoly_update_aad( &operation->ctx.chachapoly,
                                                                      input,
                                                                      input_length ) );
    }
    else
#endif /* MBEDTLS_PSA_BUILTIN_ALG_CHACHA20_POLY1305 */
    {
        (void) input;
        (void) input_length;

        return ( PSA_ERROR_NOT_SUPPORTED );
    }

    if( status == PSA_SUCCESS )
    {
        operation->ad_started = 1;
    }

    return ( status );
}

/* Encrypt or decrypt a message fragment in an active multipart AEAD
 * operation.*/
psa_status_t mbedtls_psa_aead_update( psa_aead_operation_t *operation,
                                      const uint8_t *input,
                                      size_t input_length,
                                      uint8_t *output,
                                      size_t output_size,
                                      size_t *output_length )
{
    size_t update_output_size;
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    update_output_size = PSA_AEAD_UPDATE_OUTPUT_SIZE(operation->key_type,
                                                     operation->alg, input_length);

    if(update_output_size > output_size )
    {
        return ( PSA_ERROR_BUFFER_TOO_SMALL );
    }

    if( operation->lengths_set)
    {
        /* Additional data length was supplied, but not all the additional
           data was supplied.*/
        if( operation->ad_remaining != 0 )
        {
            return ( PSA_ERROR_INVALID_ARGUMENT );
        }

        /* Too much data provided. */
        if( operation->body_remaining < input_length )
        {
            return ( PSA_ERROR_INVALID_ARGUMENT );
        }

        operation->body_remaining -= input_length;
    }

#if defined(MBEDTLS_PSA_BUILTIN_ALG_GCM)
    if( operation->alg == PSA_ALG_GCM )
    {
        /* For the time being set the requirement that all of the body data
         * must be passed in in one update, rather than deal with the complexity
         * of non block size aligned updates. This will be fixed in 3.0 when
           we can change the signature of the GCM multipart functions */
        if( !operation->lengths_set || operation->body_remaining != 0 )
        {
            return( PSA_ERROR_BAD_STATE );
        }

        if( operation->ad_started )
        {
            return( PSA_ERROR_BAD_STATE );
        }

        status =  mbedtls_to_psa_error( mbedtls_gcm_update( &operation->ctx.gcm,
                                                        input_length,
                                                        input,
                                                        output ) );
    }
    else
#endif /* MBEDTLS_PSA_BUILTIN_ALG_GCM */
#if defined(MBEDTLS_PSA_BUILTIN_ALG_CCM)
    if( operation->alg == PSA_ALG_CCM )
    {
        /* CCM dooes not support multipart yet, so all the input has to be
           passed in in one go. Store the data for the final step.*/
        if( operation->ad_started )
        {
            return( PSA_ERROR_BAD_STATE );
        }

        /* Save the additional data for later, this will be passed in
           when we have the body. */
        operation->data_buffer = ( uint8_t * ) mbedtls_calloc(1, input_length );

        if( operation->data_buffer )
        {
            memcpy( operation->data_buffer, input, input_length );
            operation->data_length = input_length;
        }
        else
        {
            return ( PSA_ERROR_INSUFFICIENT_MEMORY );
        }

    }
    else
#endif /* MBEDTLS_PSA_BUILTIN_ALG_CCM */
#if defined(MBEDTLS_PSA_BUILTIN_ALG_CHACHA20_POLY1305)
    if( operation->alg == PSA_ALG_CHACHA20_POLY1305 )
    {
        status = mbedtls_to_psa_error( mbedtls_chachapoly_update( &operation->ctx.chachapoly,
                                                                  input_length,
                                                                  input,
                                                                  output ) );
    }
    else
#endif /* MBEDTLS_PSA_BUILTIN_ALG_CHACHA20_POLY1305 */
    {
        (void) input;
        (void) input_length;

        return ( PSA_ERROR_NOT_SUPPORTED );
    }

    if( status == PSA_SUCCESS )
    {
        *output_length = update_output_size;
        operation->body_started = 1;
    }

    return( status );
}

/* Common checks for both mbedtls_psa_aead_finish() and
   mbedtls_psa_aead_verify() */
static psa_status_t mbedtls_psa_aead_finish_checks( psa_aead_operation_t *operation,
                                                    size_t output_size,
                                                    size_t tag_size,
                                                    size_t *finish_output_size,
                                                    size_t *output_tag_length )
{
    if( operation->lengths_set )
    {
        if( operation->ad_remaining != 0 || operation->body_remaining != 0 )
        {
            return( PSA_ERROR_BAD_STATE );
        }
    }

    *output_tag_length = operation->tag_length;

    if( tag_size < *output_tag_length)
    {
        return ( PSA_ERROR_BUFFER_TOO_SMALL );
    }

    if( operation->is_encrypt )
    {
        *finish_output_size = PSA_AEAD_FINISH_OUTPUT_SIZE(operation->key_type,
                                                          operation->alg);
    }
    else
    {
        *finish_output_size = PSA_AEAD_VERIFY_OUTPUT_SIZE(operation->key_type,
                                                          operation->alg);
    }

    if( output_size < *finish_output_size )
    {
        return ( PSA_ERROR_BUFFER_TOO_SMALL );
    }

    return ( PSA_SUCCESS );

}

/* Finish encrypting a message in a multipart AEAD operation. */
psa_status_t mbedtls_psa_aead_finish( psa_aead_operation_t *operation,
                                      uint8_t *ciphertext,
                                      size_t ciphertext_size,
                                      size_t *ciphertext_length,
                                      uint8_t *tag,
                                      size_t tag_size,
                                      size_t *tag_length )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    size_t output_tag_length;
    size_t finish_output_size;

    status = mbedtls_psa_aead_finish_checks( operation, ciphertext_size, tag_size, &finish_output_size,
                                             &output_tag_length);

    if( status != PSA_SUCCESS )
    {
        return status;
    }

#if defined(MBEDTLS_PSA_BUILTIN_ALG_GCM)
    if( operation->alg == PSA_ALG_GCM )
    {
        /* We will need to do final GCM pass in here when multipart is done. */
        status =  mbedtls_to_psa_error( mbedtls_gcm_finish( &operation->ctx.gcm,
                                                            tag,
                                                            tag_size ) );
    }
    else
#endif /* MBEDTLS_PSA_BUILTIN_ALG_GCM */
#if defined(MBEDTLS_PSA_BUILTIN_ALG_CCM)
    if( operation->alg == PSA_ALG_CCM )
    {
        if( !operation->ad_buffer || !operation->data_buffer )
        {
            return( PSA_ERROR_BAD_STATE );
        }

        /* Perform oneshot CCM encryption with data already stored, as
           CCM does not support multipart yet.*/
        status = mbedtls_to_psa_error( mbedtls_ccm_encrypt_and_tag( &operation->ctx.ccm,
                                                                    operation->data_length,
                                                                    operation->nonce,
                                                                    operation->nonce_length,
                                                                    operation->ad_buffer,
                                                                    operation->ad_length,
                                                                    operation->data_buffer,
                                                                    ciphertext,
                                                                    tag, tag_size ) );

        /* Even if the above operation fails, we no longer need the data */
        mbedtls_free(operation->ad_buffer);
        operation->ad_buffer = NULL;
        operation->ad_length = 0;

        mbedtls_free(operation->data_buffer);
        operation->data_buffer = NULL;
        operation->data_length = 0;
    }
    else
#endif /* MBEDTLS_PSA_BUILTIN_ALG_CCM */
#if defined(MBEDTLS_PSA_BUILTIN_ALG_CHACHA20_POLY1305)
    if( operation->alg == PSA_ALG_CHACHA20_POLY1305 )
    {
        status = mbedtls_to_psa_error( mbedtls_chachapoly_finish( &operation->ctx.chachapoly,
                                                                  tag ) );
    }
    else
#endif /* MBEDTLS_PSA_BUILTIN_ALG_CHACHA20_POLY1305 */
    {
        ( void ) ciphertext;
        ( void ) ciphertext_size;
        ( void ) ciphertext_length;
        ( void ) tag;
        ( void ) tag_size;
        ( void ) tag_length;

        return ( PSA_ERROR_NOT_SUPPORTED );
    }

    if( status == PSA_SUCCESS )
    {
        *ciphertext_length = finish_output_size;
        *tag_length = output_tag_length;
    }

    mbedtls_psa_aead_abort(operation);

    return ( status );
}

/* Finish authenticating and decrypting a message in a multipart AEAD
 * operation.*/
psa_status_t mbedtls_psa_aead_verify( psa_aead_operation_t *operation,
                                      uint8_t *plaintext,
                                      size_t plaintext_size,
                                      size_t *plaintext_length,
                                      const uint8_t *tag,
                                      size_t tag_length )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    size_t finish_output_size;
    size_t output_tag_length;

    int do_tag_check = 1;
    uint8_t check_tag[16];

    status = mbedtls_psa_aead_finish_checks( operation, plaintext_size, tag_length, &finish_output_size,
                                             &output_tag_length);

    if( status != PSA_SUCCESS )
    {
        return status;
    }

#if defined(MBEDTLS_PSA_BUILTIN_ALG_GCM)
    if( operation->alg == PSA_ALG_GCM )
    {
        /* Call finish to get the tag for comparison */
        status =  mbedtls_to_psa_error( mbedtls_gcm_finish( &operation->ctx.gcm,
                                                            check_tag,
                                                            16 ) );
    }
    else
#endif /* MBEDTLS_PSA_BUILTIN_ALG_GCM */
#if defined(MBEDTLS_PSA_BUILTIN_ALG_CCM)
    if( operation->alg == PSA_ALG_CCM )
    {
        if( !operation->ad_buffer || !operation->data_buffer )
        {
            return( PSA_ERROR_BAD_STATE );
        }

        /* Perform oneshot CCM decryption with data already stored, as
           CCM does not support multipart yet.*/

        ret = mbedtls_ccm_auth_decrypt( &operation->ctx.ccm, operation->data_length,
                                       operation->nonce, operation->nonce_length,
                                       operation->ad_buffer, operation->ad_length,
                                       operation->data_buffer, plaintext,
                                       tag, tag_length );

        if( ret == MBEDTLS_ERR_CCM_AUTH_FAILED )
        {
            status = PSA_ERROR_INVALID_SIGNATURE;
        }
        else
        {
            status = mbedtls_to_psa_error( ret );
            do_tag_check = 0;
        }

        /* Even if the above operation fails, we no longer need the data */
        mbedtls_free(operation->ad_buffer);
        operation->ad_buffer = NULL;
        operation->ad_length = 0;

        mbedtls_free(operation->data_buffer);
        operation->data_buffer = NULL;
        operation->data_length = 0;
    }
    else
#endif /* MBEDTLS_PSA_BUILTIN_ALG_CCM */
#if defined(MBEDTLS_PSA_BUILTIN_ALG_CHACHA20_POLY1305)
    if( operation->alg == PSA_ALG_CHACHA20_POLY1305 )
    {
        // call finish to get the tag for comparison.
        status = mbedtls_to_psa_error( mbedtls_chachapoly_finish( &operation->ctx.chachapoly,
                                                                  check_tag ) );
    }
    else
#endif /* MBEDTLS_PSA_BUILTIN_ALG_CHACHA20_POLY1305 */
    {
        ( void ) plaintext;
        ( void ) plaintext_size;
        ( void ) plaintext_length;
        ( void ) tag;
        ( void ) tag_length;

        return ( PSA_ERROR_NOT_SUPPORTED );
    }

    if( status == PSA_SUCCESS )
    {
        if( do_tag_check && safer_memcmp(tag, check_tag, tag_length) != 0 )
        {
            status = PSA_ERROR_INVALID_SIGNATURE;
        }
    }

    mbedtls_psa_aead_abort(operation);

    return ( status );
}

/* Abort an AEAD operation */
psa_status_t mbedtls_psa_aead_abort( psa_aead_operation_t *operation )
{
    switch( operation->alg )
    {
#if defined(MBEDTLS_PSA_BUILTIN_ALG_CCM)
        case PSA_ALG_CCM:
            mbedtls_ccm_free( &operation->ctx.ccm );
            break;
#endif /* MBEDTLS_PSA_BUILTIN_ALG_CCM */
#if defined(MBEDTLS_PSA_BUILTIN_ALG_GCM)
        case PSA_ALG_GCM:
            mbedtls_gcm_free( &operation->ctx.gcm );
            break;
#endif /* MBEDTLS_PSA_BUILTIN_ALG_GCM */
#if defined(MBEDTLS_PSA_BUILTIN_ALG_CHACHA20_POLY1305)
        case PSA_ALG_CHACHA20_POLY1305:
            mbedtls_chachapoly_free( &operation->ctx.chachapoly );
            break;
#endif /* MBEDTLS_PSA_BUILTIN_ALG_CHACHA20_POLY1305 */
    }

    return( PSA_SUCCESS );
}

#endif /* MBEDTLS_PSA_CRYPTO_C */

