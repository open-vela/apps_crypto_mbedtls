/**
 * \file common.h
 *
 * \brief Utility macros for internal use in the library
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

#ifndef MBEDTLS_LIBRARY_COMMON_H
#define MBEDTLS_LIBRARY_COMMON_H

#include "mbedtls/build_info.h"
#include "alignment.h"

#include <stdint.h>
#include <stddef.h>

#if ( defined(__ARMCC_VERSION) || defined(_MSC_VER) ) && \
     !defined(inline) && !defined(__cplusplus)
#define inline __inline
#endif

/** Helper to define a function as static except when building invasive tests.
 *
 * If a function is only used inside its own source file and should be
 * declared `static` to allow the compiler to optimize for code size,
 * but that function has unit tests, define it with
 * ```
 * MBEDTLS_STATIC_TESTABLE int mbedtls_foo(...) { ... }
 * ```
 * and declare it in a header in the `library/` directory with
 * ```
 * #if defined(MBEDTLS_TEST_HOOKS)
 * int mbedtls_foo(...);
 * #endif
 * ```
 */
#if defined(MBEDTLS_TEST_HOOKS)
#define MBEDTLS_STATIC_TESTABLE
#else
#define MBEDTLS_STATIC_TESTABLE static
#endif

#if defined(MBEDTLS_TEST_HOOKS)
extern void (*mbedtls_test_hook_test_fail)( const char * test, int line, const char * file );
#define MBEDTLS_TEST_HOOK_TEST_ASSERT( TEST ) \
       do { \
            if( ( ! ( TEST ) ) && ( ( *mbedtls_test_hook_test_fail ) != NULL ) ) \
            { \
              ( *mbedtls_test_hook_test_fail )( #TEST, __LINE__, __FILE__ ); \
            } \
    } while( 0 )
#else
#define MBEDTLS_TEST_HOOK_TEST_ASSERT( TEST )
#endif /* defined(MBEDTLS_TEST_HOOKS) */

/** Allow library to access its structs' private members.
 *
 * Although structs defined in header files are publicly available,
 * their members are private and should not be accessed by the user.
 */
#define MBEDTLS_ALLOW_PRIVATE_ACCESS

/**
 * Perform a fast block XOR operation, such that
 * r[i] = a[i] ^ b[i] where 0 <= i < n
 *
 * \param   r Pointer to result (buffer of at least \p n bytes). \p r
 *            may be equal to either \p a or \p b, but behaviour when
 *            it overlaps in other ways is undefined.
 * \param   a Pointer to input (buffer of at least \p n bytes)
 * \param   b Pointer to input (buffer of at least \p n bytes)
 * \param   n Number of bytes to process.
 */
inline void mbedtls_xor( unsigned char *r, unsigned char const *a, unsigned char const *b, size_t n )
{
    size_t i;
    for ( i = 0; ( i + 4 ) <= n; i += 4 )
    {
        uint32_t x = mbedtls_get_unaligned_uint32( a + i ) ^ mbedtls_get_unaligned_uint32( b + i );
        mbedtls_put_unaligned_uint32( r + i, x );
    }
    for ( ; i < n; i++ )
    {
        r[i] = a[i] ^ b[i];
    }
}

/* Fix MSVC C99 compatible issue
 *      MSVC support __func__ from visual studio 2015( 1900 )
 *      Use MSVC predefine macro to avoid name check fail.
 */
#if (defined(_MSC_VER) && ( _MSC_VER <= 1900 ))
#define /*no-check-names*/ __func__ __FUNCTION__
#endif

#endif /* MBEDTLS_LIBRARY_COMMON_H */
