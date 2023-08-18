/**
 * \file x509_crt_pool.h
 *
 * \brief This file contains x509_crt_pool definitions and functions.
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
#ifndef MBEDTLS_X509_CRT_POOL_H
#define MBEDTLS_X509_CRT_POOL_H

#include <stdint.h>

unsigned char *x509_crt_pool_ref_buf(const unsigned char *buf, size_t buflen);
void x509_crt_pool_unref_buf(const unsigned char *buf);

#endif /* mbedtls_x509_crt_pool.h */
