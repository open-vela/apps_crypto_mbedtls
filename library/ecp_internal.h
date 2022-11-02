/**
 * \file ecp_internal.h
 *
 * \brief Function declarations for internal functions of elliptic curve
 * point arithmetic.
 */
/**
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

#ifndef MBEDTLS_ECP_INTERNAL_H
#define MBEDTLS_ECP_INTERNAL_H

#include "common.h"
#include "mbedtls/bignum.h"
#include "bignum_mod.h"

/** Convert an MPI to its canonical representative.
 *
 * \note Currently handles the case when `N->int_rep` is
 * MBEDTLS_MPI_MOD_REP_MONTGOMERY.
 *
 * \param[in,out] X     The address of the MPI to be converted. Must have the
 *                      same number of limbs as \p N.
 * \param[in]     N     The address of the modulus.
 *
 * \return      \c 0 if successful.
 * \return      #MBEDTLS_ERR_MPI_BAD_INPUT_DATA if \p N is invalid.
 */
int mbedtls_ecp_quasi_reduction(mbedtls_mpi_uint *X,
                                const mbedtls_mpi_mod_modulus *N);

#endif /* MBEDTLS_ECP_INTERNAL_H */