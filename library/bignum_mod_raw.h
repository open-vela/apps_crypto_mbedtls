/**
 *  Low-level modular bignum functions
 *
 *  This interface should only be used by the higher-level modular bignum
 *  module (bignum_mod.c) and the ECP module (ecp.c, ecp_curves.c). All other
 *  modules should use the high-level modular bignum interface (bignum_mod.h)
 *  or the legacy bignum interface (bignum.h).
 *
 * This is a low-level interface to operations on integers modulo which
 * has no protection against passing invalid arguments such as arrays of
 * the wrong size. The functions in bignum_mod.h provide a higher-level
 * interface that includes protections against accidental misuse, at the
 * expense of code size and sometimes more cumbersome memory management.
 *
 * The functions in this module obey the following conventions unless
 * explicitly indicated otherwise:
 * - **Modulus parameters**: the modulus is passed as a pointer to a structure
 *   of type #mbedtls_mpi_mod_modulus. The structure must be setup with an
 *   array of limbs storing the bignum value of the modulus. Unless otherwise
 *   specified, the modulus is called \p N and is input-only.
 * - **Bignum parameters**: Bignums are passed as pointers to an array of
 *   limbs. A limb has the type #mbedtls_mpi_uint. Unless otherwise specified:
 *     - Bignum parameters called \p A, \p B, ... are inputs, and are not
 *       modified by the function.
 *     - Bignum parameters called \p X, \p Y are outputs or input-output.
 *       The initial content of output-only parameters is ignored.
 *     - \p T is a temporary storage area. The initial content of such
 *       parameter is ignored and the final content is unspecified.
 * - **Bignum sizes**: bignum sizes are always expressed by the \p limbs
 *   member of the modulus argument. Any bignum parameters must have the same
 *   number of limbs as the modulus. All bignum sizes must be at least 1 and
 *   must be significantly less than #SIZE_MAX. The behavior if a size is 0 is
 *   undefined.
 * - **Bignum representation**: the representation of inputs and outputs is
 *   specified by the \p int_rep field of the modulus for arithmetic
 *   functions. Utility functions may allow for different representation.
 * - **Parameter ordering**: for bignum parameters, outputs come before inputs.
 *   Temporaries come last.
 * - **Aliasing**: in general, output bignums may be aliased to one or more
 *   inputs. Modulus values may not be aliased to any other parameter. Outputs
 *   may not be aliased to one another. Temporaries may not be aliased to any
 *   other parameter.
 * - **Overlap**: apart from aliasing of limb array pointers (where two
 *   arguments are equal pointers), overlap is not supported and may result
 *   in undefined behavior.
 * - **Error handling**: This is a low-level module. Functions generally do not
 *   try to protect against invalid arguments such as nonsensical sizes or
 *   null pointers. Note that passing bignums with a different size than the
 *   modulus may lead to buffer overflows. Some functions which allocate
 *   memory or handle reading/writing of bignums will return an error if
 *   memory allocation fails or if buffer sizes are invalid.
 * - **Modular representatives**: functions that operate modulo \p N expect
 *   all modular inputs to be in the range [0, \p N - 1] and guarantee outputs
 *   in the range [0, \p N - 1]. If an input is out of range, outputs are
 *   fully unspecified, though bignum values out of range should not cause
 *   buffer overflows (beware that this is not extensively tested).
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

#ifndef MBEDTLS_BIGNUM_MOD_RAW_H
#define MBEDTLS_BIGNUM_MOD_RAW_H

#include "common.h"

#if defined(MBEDTLS_BIGNUM_C)
#include "mbedtls/bignum.h"
#endif

#include "bignum_mod.h"

/**
 * \brief   Perform a safe conditional copy of an MPI which doesn't reveal
 *          whether the assignment was done or not.
 *
 * The size to copy is determined by \p N.
 *
 * \param[out] X        The address of the destination MPI.
 *                      This must be initialized. Must have enough limbs to
 *                      store the full value of \p A.
 * \param[in]  A        The address of the source MPI. This must be initialized.
 * \param[in]  N        The address of the modulus related to \p X and \p A.
 * \param      assign   The condition deciding whether to perform the
 *                      assignment or not. Must be either 0 or 1:
 *                      * \c 1: Perform the assignment `X = A`.
 *                      * \c 0: Keep the original value of \p X.
 *
 * \note           This function avoids leaking any information about whether
 *                 the assignment was done or not.
 *
 * \warning        If \p assign is neither 0 nor 1, the result of this function
 *                 is indeterminate, and the resulting value in \p X might be
 *                 neither its original value nor the value in \p A.
 */
void mbedtls_mpi_mod_raw_cond_assign( mbedtls_mpi_uint *X,
                                      const mbedtls_mpi_uint *A,
                                      const mbedtls_mpi_mod_modulus *N,
                                      unsigned char assign );

/**
 * \brief   Perform a safe conditional swap of two MPIs which doesn't reveal
 *          whether the swap was done or not.
 *
 * The size to swap is determined by \p N.
 *
 * \param[in,out] X     The address of the first MPI. This must be initialized.
 * \param[in,out] Y     The address of the second MPI. This must be initialized.
 * \param[in]     N     The address of the modulus related to \p X and \p Y.
 * \param         swap  The condition deciding whether to perform
 *                      the swap or not. Must be either 0 or 1:
 *                      * \c 1: Swap the values of \p X and \p Y.
 *                      * \c 0: Keep the original values of \p X and \p Y.
 *
 * \note           This function avoids leaking any information about whether
 *                 the swap was done or not.
 *
 * \warning        If \p swap is neither 0 nor 1, the result of this function
 *                 is indeterminate, and both \p X and \p Y might end up with
 *                 values different to either of the original ones.
 */
void mbedtls_mpi_mod_raw_cond_swap( mbedtls_mpi_uint *X,
                                    mbedtls_mpi_uint *Y,
                                    const mbedtls_mpi_mod_modulus *N,
                                    unsigned char swap );

/** Import X from unsigned binary data.
 *
 * The MPI needs to have enough limbs to store the full value (including any
 * most significant zero bytes in the input).
 *
 * \param[out] X        The address of the MPI. The size is determined by \p m.
 *                      (In particular, it must have at least as many limbs as
 *                      the modulus \p m.)
 * \param[in] m         The address of the modulus related to \p X.
 * \param[in] input     The input buffer to import from.
 * \param input_length  The length in bytes of \p input.
 *
 * \return       \c 0 if successful.
 * \return       #MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL if \p X isn't
 *               large enough to hold the value in \p input.
 * \return       #MBEDTLS_ERR_MPI_BAD_INPUT_DATA if the external representation
 *               of \p m is invalid or \p X is not less than \p m.
 */
int mbedtls_mpi_mod_raw_read( mbedtls_mpi_uint *X,
                              const mbedtls_mpi_mod_modulus *m,
                              const unsigned char *input,
                              size_t input_length );

/** Export A into unsigned binary data.
 *
 * \param[in] A         The address of the MPI. The size is determined by \p m.
 *                      (In particular, it must have at least as many limbs as
 *                      the modulus \p m.)
 * \param[in] m         The address of the modulus related to \p A.
 * \param[out] output   The output buffer to export to.
 * \param output_length The length in bytes of \p output.
 *
 * \return       \c 0 if successful.
 * \return       #MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL if \p output isn't
 *               large enough to hold the value of \p A.
 * \return       #MBEDTLS_ERR_MPI_BAD_INPUT_DATA if the external representation
 *               of \p m is invalid.
 */
int mbedtls_mpi_mod_raw_write( const mbedtls_mpi_uint *A,
                               const mbedtls_mpi_mod_modulus *m,
                               unsigned char *output,
                               size_t output_length );

/* BEGIN MERGE SLOT 1 */

/* END MERGE SLOT 1 */

/* BEGIN MERGE SLOT 2 */

/** \brief  Subtract two MPIs, returning the residue modulo the specified
 *          modulus.
 *
 * The size of the operation is determined by \p N. \p A and \p B must have
 * the same number of limbs as \p N.
 *
 * \p X may be aliased to \p A or \p B, or even both, but may not overlap
 * either otherwise.
 *
 * \param[out] X        The address of the result MPI.
 *                      This must be initialized. Must have enough limbs to
 *                      store the full value of the result.
 * \param[in]  A        The address of the first MPI. This must be initialized.
 * \param[in]  B        The address of the second MPI. This must be initialized.
 * \param[in]  N        The address of the modulus. Used to perform a modulo
 *                      operation on the result of the subtraction.
 */
void mbedtls_mpi_mod_raw_sub( mbedtls_mpi_uint *X,
                              const mbedtls_mpi_uint *A,
                              const mbedtls_mpi_uint *B,
                              const mbedtls_mpi_mod_modulus *N );

/* END MERGE SLOT 2 */

/* BEGIN MERGE SLOT 3 */

/* END MERGE SLOT 3 */

/* BEGIN MERGE SLOT 4 */

/* END MERGE SLOT 4 */

/* BEGIN MERGE SLOT 5 */
/**
 * \brief Perform a known-size modular addition.
 *
 * Calculate `A + B modulo N`.
 *
 * The number of limbs in each operand, and the result, is given by the
 * modulus \p N.
 *
 * \p X may be aliased to \p A or \p B, or even both, but may not overlap
 * either otherwise.
 *
 * \param[out] X    The result of the modular addition.
 * \param[in] A     Little-endian presentation of the left operand. This
 *                  must be smaller than \p N.
 * \param[in] B     Little-endian presentation of the right operand. This
 *                  must be smaller than \p N.
 * \param[in] N     The address of the modulus.
 */
void mbedtls_mpi_mod_raw_add( mbedtls_mpi_uint *X,
                              const mbedtls_mpi_uint *A,
                              const mbedtls_mpi_uint *B,
                              const mbedtls_mpi_mod_modulus *N );
/* END MERGE SLOT 5 */

/* BEGIN MERGE SLOT 6 */

/* END MERGE SLOT 6 */

/* BEGIN MERGE SLOT 7 */
/** Convert an MPI into Montgomery form.
 *
 * \param X      The address of the MPI.
 *               Must have the same number of limbs as \p m.
 * \param m      The address of the modulus, which gives the size of
 *               the base `R` = 2^(biL*m->limbs).
 *
 * \return       \c 0 if successful.
 */
int mbedtls_mpi_mod_raw_to_mont_rep( mbedtls_mpi_uint *X,
                                     const mbedtls_mpi_mod_modulus *m );

/** Convert an MPI back from Montgomery representation.
 *
 * \param X      The address of the MPI.
 *               Must have the same number of limbs as \p m.
 * \param m      The address of the modulus, which gives the size of
 *               the base `R`= 2^(biL*m->limbs).
 *
 * \return       \c 0 if successful.
 */
int mbedtls_mpi_mod_raw_from_mont_rep( mbedtls_mpi_uint *X,
                                       const mbedtls_mpi_mod_modulus *m );

/** \brief  Perform fixed width modular negation.
 *
 * The size of the operation is determined by \p m. \p A must have
 * the same number of limbs as \p m.
 *
 * \p X may be aliased to \p A.
 *
 * \param[out] X        The result of the modular negation.
 *                      This must be initialized.
 * \param[in] A         Little-endian presentation of the input operand. This
 *                      must be less than or equal to \p m.
 * \param[in] m         The modulus to use.
 */
void mbedtls_mpi_mod_raw_neg( mbedtls_mpi_uint *X,
                              const mbedtls_mpi_uint *A,
                              const mbedtls_mpi_mod_modulus *m);
/* END MERGE SLOT 7 */

/* BEGIN MERGE SLOT 8 */

/* END MERGE SLOT 8 */

/* BEGIN MERGE SLOT 9 */

/* END MERGE SLOT 9 */

/* BEGIN MERGE SLOT 10 */

/* END MERGE SLOT 10 */

#endif /* MBEDTLS_BIGNUM_MOD_RAW_H */
