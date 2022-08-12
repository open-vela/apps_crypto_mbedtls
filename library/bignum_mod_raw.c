/*
 *  Multi-precision integer library
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

#if defined(MBEDTLS_BIGNUM_C)

#include <string.h>

#include "mbedtls/error.h"
#include "mbedtls/platform_util.h"

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#include <stdlib.h>
#define mbedtls_printf      printf
#define mbedtls_calloc      calloc
#define mbedtls_free        free
#endif

#include "bignum_core.h"
#include "bignum_mod_raw.h"
#include "bignum_mod.h"
#include "constant_time_internal.h"

int mbedtls_mpi_mod_raw_read( mbedtls_mpi_uint *X,
                              mbedtls_mpi_mod_modulus *m,
                              unsigned char *buf,
                              size_t buflen )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    switch( m->ext_rep )
    {
        case MBEDTLS_MPI_MOD_EXT_REP_LE:
            ret = mbedtls_mpi_core_read_le( X, m->n, buf, buflen );
            break;
        case MBEDTLS_MPI_MOD_EXT_REP_BE:
            ret = mbedtls_mpi_core_read_be( X, m->n, buf, buflen );
            break;
        default:
            return( MBEDTLS_ERR_MPI_BAD_INPUT_DATA );
    }

    if( ret != 0 )
        goto cleanup;

    if( !mbedtls_mpi_core_lt_ct( X, m->p, m->n ) )
    {
        ret = MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
        goto cleanup;
    }

cleanup:

    return( ret );
}

int mbedtls_mpi_mod_raw_write( mbedtls_mpi_uint *X,
                               mbedtls_mpi_mod_modulus *m,
                               unsigned char *buf,
                               size_t buflen )
{
    switch( m->ext_rep )
    {
        case MBEDTLS_MPI_MOD_EXT_REP_LE:
            return( mbedtls_mpi_core_write_le( X, m->n, buf, buflen ) );
        case MBEDTLS_MPI_MOD_EXT_REP_BE:
            return( mbedtls_mpi_core_write_be( X, m->n, buf, buflen ) );
        default:
            return( MBEDTLS_ERR_MPI_BAD_INPUT_DATA );
    }
}

#endif /* MBEDTLS_BIGNUM_C */