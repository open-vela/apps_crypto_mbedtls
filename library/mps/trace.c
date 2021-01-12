/*
 *  Message Processing Stack, Trace module
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
 *
 *  This file is part of Mbed TLS (https://tls.mbed.org)
 */

#include "common.h"

#if defined(MBEDTLS_MPS_TRACE)

#include "trace.h"
#include <stdarg.h>

static int trace_depth_ = 0;

#define color_default  "\x1B[0m"
#define color_red      "\x1B[1;31m"
#define color_green    "\x1B[1;32m"
#define color_yellow   "\x1B[1;33m"
#define color_blue     "\x1B[1;34m"
#define color_magenta  "\x1B[1;35m"
#define color_cyan     "\x1B[1;36m"
#define color_white    "\x1B[1;37m"

static char const * colors[] =
{
    color_default,
    color_green,
    color_yellow,
    color_magenta,
    color_cyan,
    color_blue,
    color_white
};

#define MPS_TRACE_BUF_SIZE 100

void trace_print_msg( int id, int line, const char *format, ... )
{
    int ret;
    char str[MPS_TRACE_BUF_SIZE];
    va_list argp;
    va_start( argp, format );
    ret = mbedtls_vsnprintf( str, MPS_TRACE_BUF_SIZE, format, argp );
    va_end( argp );

    if( ret >= 0 && ret < MPS_TRACE_BUF_SIZE )
    {
        str[ret] = '\0';
        mbedtls_printf( "[%d|L%d]: %s\n", id, line, str );
    }
}

int trace_get_depth()
{
    return trace_depth_;
}
void trace_dec_depth()
{
    trace_depth_--;
}
void trace_inc_depth()
{
    trace_depth_++;
}

void trace_color( int id )
{
    if( id > (int) ( sizeof( colors ) / sizeof( *colors ) ) )
        return;
    printf( "%s", colors[ id ] );
}

void trace_indent( int level, trace_type ty )
{
    if( level > 0 )
    {
        while( --level )
            printf( "|  " );

        printf( "|  " );
    }

    switch( ty )
    {
        case trace_comment:
            mbedtls_printf( "@ " );
            break;

        case trace_call:
            mbedtls_printf( "+--> " );
            break;

        case trace_error:
            mbedtls_printf( "E " );
            break;

        case trace_return:
            mbedtls_printf( "< " );
            break;

        default:
            break;
    }
}

#endif /* MBEDTLS_MPS_TRACE */
