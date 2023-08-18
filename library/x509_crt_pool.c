/*
 *  X.509 certificate pool
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

#if defined(MBEDTLS_X509_CRT_POOL)

#include <sys/queue.h>
#include "mbedtls/platform.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/x509.h"
#include "x509_crt_pool.h"

#if defined(MBEDTLS_THREADING_C)
#include "mbedtls/threading.h"
#endif

struct x509_crt_pool_item {
    mbedtls_x509_buf raw;
    uint32_t ref_count;
    SLIST_ENTRY(x509_crt_pool_item) next;
};

struct x509_crt_pool {
    SLIST_HEAD(x509_crt_pool_list, x509_crt_pool_item) head;
};

static struct x509_crt_pool x509_crt_pool_s = {
    .head = SLIST_HEAD_INITIALIZER(x509_crt_pool_s.head),
};

static struct x509_crt_pool_item *x509_crt_pool_item_create(const unsigned char *buf,
                                                            size_t buflen)
{
    struct x509_crt_pool_item *item;

    item = mbedtls_calloc(1, sizeof(struct x509_crt_pool_item));
    if (item == NULL)
    {
        return NULL;
    }

    item->raw.len = buflen;
    item->raw.p = mbedtls_calloc(1, item->raw.len);
    if (item->raw.p == NULL)
    {
        mbedtls_free(item);
        return NULL;
    }

    memcpy(item->raw.p, buf, item->raw.len);
    item->ref_count = 1;
    SLIST_INSERT_HEAD(&x509_crt_pool_s.head, item, next);
    return item;
}

static void x509_crt_pool_item_free(struct x509_crt_pool_item *item)
{
    SLIST_REMOVE(&x509_crt_pool_s.head, item, x509_crt_pool_item, next);
    mbedtls_platform_zeroize(item->raw.p, item->raw.len);
    mbedtls_free(item->raw.p);
    mbedtls_free(item);
}

unsigned char *x509_crt_pool_ref_buf(const unsigned char *buf, size_t buflen)
{
    struct x509_crt_pool_item *item;

#if defined(MBEDTLS_THREADING_C)
    if (mbedtls_mutex_lock(&mbedtls_threading_x509crtpool_mutex) != 0)
    {
        return NULL;
    }
#endif

    SLIST_FOREACH(item, &x509_crt_pool_s.head, next)
    if (item->raw.len == buflen)
    {
        if (memcmp(item->raw.p, buf, buflen) == 0)
        {
            item->ref_count++;
            goto unlock;
        }
    }

    item = x509_crt_pool_item_create(buf, buflen);

unlock:
#if defined(MBEDTLS_THREADING_C)
    if (mbedtls_mutex_unlock(&mbedtls_threading_x509crtpool_mutex) != 0)
    {
        return NULL;
    }
#endif

    return item == NULL ? NULL : item->raw.p;
}

void x509_crt_pool_unref_buf(const unsigned char *buf)
{
    struct x509_crt_pool_item *item;

#if defined(MBEDTLS_THREADING_C)
    if (mbedtls_mutex_lock(&mbedtls_threading_x509crtpool_mutex) != 0)
    {
        return;
    }
#endif

    SLIST_FOREACH(item, &x509_crt_pool_s.head, next)
    if (item->raw.p == buf)
    {
        item->ref_count--;
        if (item->ref_count == 0)
        {
            x509_crt_pool_item_free(item);
        }
        break;
    }

#if defined(MBEDTLS_THREADING_C)
    mbedtls_mutex_unlock(&mbedtls_threading_x509crtpool_mutex);
#endif
}

#endif /* MBEDTLS_X509_CRT_POOL */
