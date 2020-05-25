#!/bin/sh
#
# Copyright (C) 2015-2019, Arm Limited, All Rights Reserved
#
# This file is part of Mbed TLS (https://tls.mbed.org)

set -eu

if [ -d include/mbedtls ]; then :; else
    echo "$0: must be run from root" >&2
    exit 1
fi

HEADERS=$( ls include/mbedtls/*.h include/psa/*.h | egrep -v 'compat-1\.3\.h' )
HEADERS="$HEADERS 3rdparty/everest/include/everest/everest.h 3rdparty/everest/include/everest/x25519.h"

sed -n -e 's/.*#define \([a-zA-Z0-9_]*\).*/\1/p' $HEADERS \
    | egrep -v '^(asm|inline|EMIT|_CRT_SECURE_NO_DEPRECATE)$|^MULADDC_' \
    | sort -u > macros

wc -l macros
