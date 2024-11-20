/**
 * \file ssl_invasive.h
 *
 * \brief SSL module: interfaces for invasive testing only.
 *
 * The interfaces in this file are intended for testing purposes only.
 * They SHOULD NOT be made available in library integrations except when
 * building the library for testing.
 */
/*
 *  Copyright (C) 2020, ARM Limited, All Rights Reserved
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
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */
#ifndef MBEDTLS_SSL_INVASIVE_H
#define MBEDTLS_SSL_INVASIVE_H

#include "common.h"
#include "mbedtls/md.h"

#if defined(MBEDTLS_TEST_HOOKS) &&              \
    defined(MBEDTLS_SSL_SOME_SUITES_USE_CBC) && \
    ( defined(MBEDTLS_SSL_PROTO_TLS1) ||        \
      defined(MBEDTLS_SSL_PROTO_TLS1_1) |       \
      defined(MBEDTLS_SSL_PROTO_TLS1_2) )
/** \brief Compute the HMAC of variable-length data with constant flow.
 *
 * This function computes the HMAC of the concatenation of \p add_data and \p
 * data, and does with a code flow and memory access pattern that does not
 * depend on \p data_len_secret, but only on \p min_data_len and \p
 * max_data_len. In particular, this function always reads exactly \p
 * max_data_len bytes from \p data.
 *
 * \param ctx               The HMAC context. It must have keys configured
 *                          with mbedtls_md_hmac_starts(). It is reset using
 *                          mbedtls_md_hmac_reset() after the computation is
 *                          complete to prepare for the next computation.
 * \param add_data          The additional data prepended to \p data. This
 *                          must point to a readable buffer of \p add_data_len
 *                          bytes.
 * \param add_data_len      The length of \p add_data in bytes.
 * \param data              The data appended to \p add_data. This must point
 *                          to a readable buffer of \p max_data_len bytes.
 * \param data_len_secret   The length of the data to process in \p data.
 *                          This must be no less than \p min_data_len and no
 *                          greated than \p max_data_len.
 * \param min_data_len      The minimal length of \p data in bytes.
 * \param max_data_len      The maximal length of \p data in bytes.
 * \param output            The HMAC will be written here. This must point to
 *                          a writeable buffer of sufficient size to hold the
 *                          HMAC value.
 *
 * \retval 0
 *         Success.
 * \retval MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED
 *         The hardware accelerator failed.
 */
int mbedtls_ssl_cf_hmac(
        mbedtls_md_context_t *ctx,
        const unsigned char *add_data, size_t add_data_len,
        const unsigned char *data, size_t data_len_secret,
        size_t min_data_len, size_t max_data_len,
        unsigned char *output );
#endif /* MBEDTLS_TEST_HOOKS && MBEDTLS_SSL_SOME_SUITES_USE_CBC && TLS 1.0-1.2 */

#endif /* MBEDTLS_SSL_INVASIVE_H */
