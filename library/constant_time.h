/**
 *  Constant-time functions
 *
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

#include <stddef.h>

int mbedtls_ssl_safer_memcmp( const void *a, const void *b, size_t n );

int mbedtls_constant_time_memcmp( const void *v1, const void *v2, size_t len );

unsigned char mbedtls_nist_kw_safer_memcmp( const void *a, const void *b, size_t n );

int mbedtls_safer_memcmp( const void *a, const void *b, size_t n );


unsigned mbedtls_cf_uint_mask( unsigned value );

size_t mbedtls_cf_size_mask( size_t bit );

size_t mbedtls_cf_size_mask_lt( size_t x, size_t y );
