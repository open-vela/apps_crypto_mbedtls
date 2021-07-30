#!/usr/bin/env python3

# test_translate_ciphers_names.py
#
# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""
Test translate_ciphers.py by running every Mbed TLS ciphersuite name
combination through the translate functions and comparing them to their
correct GNUTLS or OpenSSL counterpart.
"""
import sys
from translate_ciphers import translate_gnutls, translate_ossl

def assert_equal(translate, original):
    """
    Compare the translated ciphersuite name against the original
    On fail, print the mismatch on the screen to directly compare the
    differences
    """
    try:
        assert translate == original
    except AssertionError:
        print("%s\n%s\n" %(translate, original))
        sys.exit(1)

def test_all_common():
    """
    Translate the Mbed TLS ciphersuite names to the common OpenSSL and
    GnuTLS ciphersuite names, and compare them with the true, expected
    corresponding OpenSSL and GnuTLS ciphersuite names
    """
    ciphers = [
        ("TLS-ECDHE-ECDSA-WITH-NULL-SHA",
         "+ECDHE-ECDSA:+NULL:+SHA1",
         "ECDHE-ECDSA-NULL-SHA"),
        ("TLS-ECDHE-ECDSA-WITH-3DES-EDE-CBC-SHA",
         "+ECDHE-ECDSA:+3DES-CBC:+SHA1",
         "ECDHE-ECDSA-DES-CBC3-SHA"),
        ("TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA",
         "+ECDHE-ECDSA:+AES-128-CBC:+SHA1",
         "ECDHE-ECDSA-AES128-SHA"),
        ("TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA",
         "+ECDHE-ECDSA:+AES-256-CBC:+SHA1",
         "ECDHE-ECDSA-AES256-SHA"),
        ("TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA256",
         "+ECDHE-ECDSA:+AES-128-CBC:+SHA256",
         "ECDHE-ECDSA-AES128-SHA256"),
        ("TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA384",
         "+ECDHE-ECDSA:+AES-256-CBC:+SHA384",
         "ECDHE-ECDSA-AES256-SHA384"),
        ("TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256",
         "+ECDHE-ECDSA:+AES-128-GCM:+AEAD",
         "ECDHE-ECDSA-AES128-GCM-SHA256"),
        ("TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384",
         "+ECDHE-ECDSA:+AES-256-GCM:+AEAD",
         "ECDHE-ECDSA-AES256-GCM-SHA384"),
        ("TLS-DHE-RSA-WITH-AES-128-CBC-SHA",
         "+DHE-RSA:+AES-128-CBC:+SHA1",
         "DHE-RSA-AES128-SHA"),
        ("TLS-DHE-RSA-WITH-AES-256-CBC-SHA",
         "+DHE-RSA:+AES-256-CBC:+SHA1",
         "DHE-RSA-AES256-SHA"),
        ("TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA",
         "+DHE-RSA:+CAMELLIA-128-CBC:+SHA1",
         "DHE-RSA-CAMELLIA128-SHA"),
        ("TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA",
         "+DHE-RSA:+CAMELLIA-256-CBC:+SHA1",
         "DHE-RSA-CAMELLIA256-SHA"),
        ("TLS-DHE-RSA-WITH-3DES-EDE-CBC-SHA",
         "+DHE-RSA:+3DES-CBC:+SHA1",
         "EDH-RSA-DES-CBC3-SHA"),
        ("TLS-RSA-WITH-AES-256-CBC-SHA",
         "+RSA:+AES-256-CBC:+SHA1",
         "AES256-SHA"),
        ("TLS-RSA-WITH-CAMELLIA-256-CBC-SHA",
         "+RSA:+CAMELLIA-256-CBC:+SHA1",
         "CAMELLIA256-SHA"),
        ("TLS-RSA-WITH-AES-128-CBC-SHA",
         "+RSA:+AES-128-CBC:+SHA1",
         "AES128-SHA"),
        ("TLS-RSA-WITH-CAMELLIA-128-CBC-SHA",
         "+RSA:+CAMELLIA-128-CBC:+SHA1",
         "CAMELLIA128-SHA"),
        ("TLS-RSA-WITH-3DES-EDE-CBC-SHA",
         "+RSA:+3DES-CBC:+SHA1",
         "DES-CBC3-SHA"),
        ("TLS-RSA-WITH-NULL-MD5",
         "+RSA:+NULL:+MD5",
         "NULL-MD5"),
        ("TLS-RSA-WITH-NULL-SHA",
         "+RSA:+NULL:+SHA1",
         "NULL-SHA"),
        ("TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA",
         "+ECDHE-RSA:+AES-128-CBC:+SHA1",
         "ECDHE-RSA-AES128-SHA"),
        ("TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA",
         "+ECDHE-RSA:+AES-256-CBC:+SHA1",
         "ECDHE-RSA-AES256-SHA"),
        ("TLS-ECDHE-RSA-WITH-3DES-EDE-CBC-SHA",
         "+ECDHE-RSA:+3DES-CBC:+SHA1",
         "ECDHE-RSA-DES-CBC3-SHA"),
        ("TLS-ECDHE-RSA-WITH-NULL-SHA",
         "+ECDHE-RSA:+NULL:+SHA1",
         "ECDHE-RSA-NULL-SHA"),
        ("TLS-RSA-WITH-AES-128-CBC-SHA256",
         "+RSA:+AES-128-CBC:+SHA256",
         "AES128-SHA256"),
        ("TLS-DHE-RSA-WITH-AES-128-CBC-SHA256",
         "+DHE-RSA:+AES-128-CBC:+SHA256",
         "DHE-RSA-AES128-SHA256"),
        ("TLS-RSA-WITH-AES-256-CBC-SHA256",
         "+RSA:+AES-256-CBC:+SHA256",
         "AES256-SHA256"),
        ("TLS-DHE-RSA-WITH-AES-256-CBC-SHA256",
         "+DHE-RSA:+AES-256-CBC:+SHA256",
         "DHE-RSA-AES256-SHA256"),
        ("TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA256",
         "+ECDHE-RSA:+AES-128-CBC:+SHA256",
         "ECDHE-RSA-AES128-SHA256"),
        ("TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA384",
         "+ECDHE-RSA:+AES-256-CBC:+SHA384",
         "ECDHE-RSA-AES256-SHA384"),
        ("TLS-RSA-WITH-AES-128-GCM-SHA256",
         "+RSA:+AES-128-GCM:+AEAD",
         "AES128-GCM-SHA256"),
        ("TLS-RSA-WITH-AES-256-GCM-SHA384",
         "+RSA:+AES-256-GCM:+AEAD",
         "AES256-GCM-SHA384"),
        ("TLS-DHE-RSA-WITH-AES-128-GCM-SHA256",
         "+DHE-RSA:+AES-128-GCM:+AEAD",
         "DHE-RSA-AES128-GCM-SHA256"),
        ("TLS-DHE-RSA-WITH-AES-256-GCM-SHA384",
         "+DHE-RSA:+AES-256-GCM:+AEAD",
         "DHE-RSA-AES256-GCM-SHA384"),
        ("TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256",
         "+ECDHE-RSA:+AES-128-GCM:+AEAD",
         "ECDHE-RSA-AES128-GCM-SHA256"),
        ("TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384",
         "+ECDHE-RSA:+AES-256-GCM:+AEAD",
         "ECDHE-RSA-AES256-GCM-SHA384"),
        ("TLS-PSK-WITH-3DES-EDE-CBC-SHA",
         "+PSK:+3DES-CBC:+SHA1",
         "PSK-3DES-EDE-CBC-SHA"),
        ("TLS-PSK-WITH-AES-128-CBC-SHA",
         "+PSK:+AES-128-CBC:+SHA1",
         "PSK-AES128-CBC-SHA"),
        ("TLS-PSK-WITH-AES-256-CBC-SHA",
         "+PSK:+AES-256-CBC:+SHA1",
         "PSK-AES256-CBC-SHA"),

        ("TLS-ECDH-ECDSA-WITH-NULL-SHA",
         None,
         "ECDH-ECDSA-NULL-SHA"),
        ("TLS-ECDH-ECDSA-WITH-3DES-EDE-CBC-SHA",
         None,
         "ECDH-ECDSA-DES-CBC3-SHA"),
        ("TLS-ECDH-ECDSA-WITH-AES-128-CBC-SHA",
         None,
         "ECDH-ECDSA-AES128-SHA"),
        ("TLS-ECDH-ECDSA-WITH-AES-256-CBC-SHA",
         None,
         "ECDH-ECDSA-AES256-SHA"),
        ("TLS-ECDH-ECDSA-WITH-AES-128-CBC-SHA256",
         None,
         "ECDH-ECDSA-AES128-SHA256"),
        ("TLS-ECDH-ECDSA-WITH-AES-256-CBC-SHA384",
         None,
         "ECDH-ECDSA-AES256-SHA384"),
        ("TLS-ECDH-ECDSA-WITH-AES-128-GCM-SHA256",
         None,
         "ECDH-ECDSA-AES128-GCM-SHA256"),
        ("TLS-ECDH-ECDSA-WITH-AES-256-GCM-SHA384",
         None,
         "ECDH-ECDSA-AES256-GCM-SHA384"),
        ("TLS-ECDHE-ECDSA-WITH-ARIA-256-GCM-SHA384",
         None,
         "ECDHE-ECDSA-ARIA256-GCM-SHA384"),
        ("TLS-ECDHE-ECDSA-WITH-ARIA-128-GCM-SHA256",
         None,
         "ECDHE-ECDSA-ARIA128-GCM-SHA256"),
        ("TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256",
         None,
         "ECDHE-ECDSA-CHACHA20-POLY1305"),
        ("TLS-RSA-WITH-DES-CBC-SHA",
         None,
         "DES-CBC-SHA"),
        ("TLS-DHE-RSA-WITH-DES-CBC-SHA",
         None,
         "EDH-RSA-DES-CBC-SHA"),
        ("TLS-ECDHE-RSA-WITH-ARIA-256-GCM-SHA384",
         None,
         "ECDHE-ARIA256-GCM-SHA384"),
        ("TLS-DHE-RSA-WITH-ARIA-256-GCM-SHA384",
         None,
         "DHE-RSA-ARIA256-GCM-SHA384"),
        ("TLS-RSA-WITH-ARIA-256-GCM-SHA384",
         None,
         "ARIA256-GCM-SHA384"),
        ("TLS-ECDHE-RSA-WITH-ARIA-128-GCM-SHA256",
         None,
         "ECDHE-ARIA128-GCM-SHA256"),
        ("TLS-DHE-RSA-WITH-ARIA-128-GCM-SHA256",
         None,
         "DHE-RSA-ARIA128-GCM-SHA256"),
        ("TLS-RSA-WITH-ARIA-128-GCM-SHA256",
         None,
         "ARIA128-GCM-SHA256"),
        ("TLS-DHE-RSA-WITH-CHACHA20-POLY1305-SHA256",
         None,
         "DHE-RSA-CHACHA20-POLY1305"),
        ("TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256",
         None,
         "ECDHE-RSA-CHACHA20-POLY1305"),
        ("TLS-DHE-PSK-WITH-ARIA-256-GCM-SHA384",
         None,
         "DHE-PSK-ARIA256-GCM-SHA384"),
        ("TLS-DHE-PSK-WITH-ARIA-128-GCM-SHA256",
         None,
         "DHE-PSK-ARIA128-GCM-SHA256"),
        ("TLS-PSK-WITH-ARIA-256-GCM-SHA384",
         None,
         "PSK-ARIA256-GCM-SHA384"),
        ("TLS-PSK-WITH-ARIA-128-GCM-SHA256",
         None,
         "PSK-ARIA128-GCM-SHA256"),
        ("TLS-PSK-WITH-CHACHA20-POLY1305-SHA256",
         None,
         "PSK-CHACHA20-POLY1305"),
        ("TLS-ECDHE-PSK-WITH-CHACHA20-POLY1305-SHA256",
         None,
         "ECDHE-PSK-CHACHA20-POLY1305"),
        ("TLS-DHE-PSK-WITH-CHACHA20-POLY1305-SHA256",
         None,
         "DHE-PSK-CHACHA20-POLY1305"),

        ("TLS-ECDHE-ECDSA-WITH-CAMELLIA-128-CBC-SHA256",
         "+ECDHE-ECDSA:+CAMELLIA-128-CBC:+SHA256",
         None),
        ("TLS-ECDHE-ECDSA-WITH-CAMELLIA-256-CBC-SHA384",
         "+ECDHE-ECDSA:+CAMELLIA-256-CBC:+SHA384",
         None),
        ("TLS-ECDHE-ECDSA-WITH-CAMELLIA-128-GCM-SHA256",
         "+ECDHE-ECDSA:+CAMELLIA-128-GCM:+AEAD",
         None),
        ("TLS-ECDHE-ECDSA-WITH-CAMELLIA-256-GCM-SHA384",
         "+ECDHE-ECDSA:+CAMELLIA-256-GCM:+AEAD",
         None),
        ("TLS-ECDHE-ECDSA-WITH-AES-128-CCM",
         "+ECDHE-ECDSA:+AES-128-CCM:+AEAD",
         None),
        ("TLS-ECDHE-ECDSA-WITH-AES-256-CCM",
         "+ECDHE-ECDSA:+AES-256-CCM:+AEAD",
         None),
        ("TLS-ECDHE-ECDSA-WITH-AES-128-CCM-8",
         "+ECDHE-ECDSA:+AES-128-CCM-8:+AEAD",
         None),
        ("TLS-ECDHE-ECDSA-WITH-AES-256-CCM-8",
         "+ECDHE-ECDSA:+AES-256-CCM-8:+AEAD",
         None),
        ("TLS-RSA-WITH-NULL-SHA256",
         "+RSA:+NULL:+SHA256",
         None),
        ("TLS-ECDHE-RSA-WITH-CAMELLIA-128-CBC-SHA256",
         "+ECDHE-RSA:+CAMELLIA-128-CBC:+SHA256",
         None),
        ("TLS-ECDHE-RSA-WITH-CAMELLIA-256-CBC-SHA384",
         "+ECDHE-RSA:+CAMELLIA-256-CBC:+SHA384",
         None),
        ("TLS-RSA-WITH-CAMELLIA-128-CBC-SHA256",
         "+RSA:+CAMELLIA-128-CBC:+SHA256",
         None),
        ("TLS-RSA-WITH-CAMELLIA-256-CBC-SHA256",
         "+RSA:+CAMELLIA-256-CBC:+SHA256",
         None),
        ("TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA256",
         "+DHE-RSA:+CAMELLIA-128-CBC:+SHA256",
         None),
        ("TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA256",
         "+DHE-RSA:+CAMELLIA-256-CBC:+SHA256",
         None),
        ("TLS-ECDHE-RSA-WITH-CAMELLIA-128-GCM-SHA256",
         "+ECDHE-RSA:+CAMELLIA-128-GCM:+AEAD",
         None),
        ("TLS-ECDHE-RSA-WITH-CAMELLIA-256-GCM-SHA384",
         "+ECDHE-RSA:+CAMELLIA-256-GCM:+AEAD",
         None),
        ("TLS-DHE-RSA-WITH-CAMELLIA-128-GCM-SHA256",
         "+DHE-RSA:+CAMELLIA-128-GCM:+AEAD",
         None),
        ("TLS-DHE-RSA-WITH-CAMELLIA-256-GCM-SHA384",
         "+DHE-RSA:+CAMELLIA-256-GCM:+AEAD",
         None),
        ("TLS-RSA-WITH-CAMELLIA-128-GCM-SHA256",
         "+RSA:+CAMELLIA-128-GCM:+AEAD",
         None),
        ("TLS-RSA-WITH-CAMELLIA-256-GCM-SHA384",
         "+RSA:+CAMELLIA-256-GCM:+AEAD",
         None),
        ("TLS-RSA-WITH-AES-128-CCM",
         "+RSA:+AES-128-CCM:+AEAD",
         None),
        ("TLS-RSA-WITH-AES-256-CCM",
         "+RSA:+AES-256-CCM:+AEAD",
         None),
        ("TLS-DHE-RSA-WITH-AES-128-CCM",
         "+DHE-RSA:+AES-128-CCM:+AEAD",
         None),
        ("TLS-DHE-RSA-WITH-AES-256-CCM",
         "+DHE-RSA:+AES-256-CCM:+AEAD",
         None),
        ("TLS-RSA-WITH-AES-128-CCM-8",
         "+RSA:+AES-128-CCM-8:+AEAD",
         None),
        ("TLS-RSA-WITH-AES-256-CCM-8",
         "+RSA:+AES-256-CCM-8:+AEAD",
         None),
        ("TLS-DHE-RSA-WITH-AES-128-CCM-8",
         "+DHE-RSA:+AES-128-CCM-8:+AEAD",
         None),
        ("TLS-DHE-RSA-WITH-AES-256-CCM-8",
         "+DHE-RSA:+AES-256-CCM-8:+AEAD",
         None),
        ("TLS-DHE-PSK-WITH-3DES-EDE-CBC-SHA",
         "+DHE-PSK:+3DES-CBC:+SHA1",
         None),
        ("TLS-DHE-PSK-WITH-AES-128-CBC-SHA",
         "+DHE-PSK:+AES-128-CBC:+SHA1",
         None),
        ("TLS-DHE-PSK-WITH-AES-256-CBC-SHA",
         "+DHE-PSK:+AES-256-CBC:+SHA1",
         None),
        ("TLS-ECDHE-PSK-WITH-AES-256-CBC-SHA",
         "+ECDHE-PSK:+AES-256-CBC:+SHA1",
         None),
        ("TLS-ECDHE-PSK-WITH-AES-128-CBC-SHA",
         "+ECDHE-PSK:+AES-128-CBC:+SHA1",
         None),
        ("TLS-ECDHE-PSK-WITH-3DES-EDE-CBC-SHA",
         "+ECDHE-PSK:+3DES-CBC:+SHA1",
         None),
        ("TLS-RSA-PSK-WITH-3DES-EDE-CBC-SHA",
         "+RSA-PSK:+3DES-CBC:+SHA1",
         None),
        ("TLS-RSA-PSK-WITH-AES-256-CBC-SHA",
         "+RSA-PSK:+AES-256-CBC:+SHA1",
         None),
        ("TLS-RSA-PSK-WITH-AES-128-CBC-SHA",
         "+RSA-PSK:+AES-128-CBC:+SHA1",
         None),
        ("TLS-ECDHE-PSK-WITH-AES-256-CBC-SHA384",
         "+ECDHE-PSK:+AES-256-CBC:+SHA384",
         None),
        ("TLS-ECDHE-PSK-WITH-CAMELLIA-256-CBC-SHA384",
         "+ECDHE-PSK:+CAMELLIA-256-CBC:+SHA384",
         None),
        ("TLS-ECDHE-PSK-WITH-AES-128-CBC-SHA256",
         "+ECDHE-PSK:+AES-128-CBC:+SHA256",
         None),
        ("TLS-ECDHE-PSK-WITH-CAMELLIA-128-CBC-SHA256",
         "+ECDHE-PSK:+CAMELLIA-128-CBC:+SHA256",
         None),
        ("TLS-ECDHE-PSK-WITH-NULL-SHA384",
         "+ECDHE-PSK:+NULL:+SHA384",
         None),
        ("TLS-ECDHE-PSK-WITH-NULL-SHA256",
         "+ECDHE-PSK:+NULL:+SHA256",
         None),
        ("TLS-PSK-WITH-AES-128-CBC-SHA256",
         "+PSK:+AES-128-CBC:+SHA256",
         None),
        ("TLS-PSK-WITH-AES-256-CBC-SHA384",
         "+PSK:+AES-256-CBC:+SHA384",
         None),
        ("TLS-DHE-PSK-WITH-AES-128-CBC-SHA256",
         "+DHE-PSK:+AES-128-CBC:+SHA256",
         None),
        ("TLS-DHE-PSK-WITH-AES-256-CBC-SHA384",
         "+DHE-PSK:+AES-256-CBC:+SHA384",
         None),
        ("TLS-PSK-WITH-NULL-SHA256",
         "+PSK:+NULL:+SHA256",
         None),
        ("TLS-PSK-WITH-NULL-SHA384",
         "+PSK:+NULL:+SHA384",
         None),
        ("TLS-DHE-PSK-WITH-NULL-SHA256",
         "+DHE-PSK:+NULL:+SHA256",
         None),
        ("TLS-DHE-PSK-WITH-NULL-SHA384",
         "+DHE-PSK:+NULL:+SHA384",
         None),
        ("TLS-RSA-PSK-WITH-AES-256-CBC-SHA384",
         "+RSA-PSK:+AES-256-CBC:+SHA384",
         None),
        ("TLS-RSA-PSK-WITH-AES-128-CBC-SHA256",
         "+RSA-PSK:+AES-128-CBC:+SHA256",
         None),
        ("TLS-RSA-PSK-WITH-NULL-SHA256",
         "+RSA-PSK:+NULL:+SHA256",
         None),
        ("TLS-RSA-PSK-WITH-NULL-SHA384",
         "+RSA-PSK:+NULL:+SHA384",
         None),
        ("TLS-DHE-PSK-WITH-CAMELLIA-128-CBC-SHA256",
         "+DHE-PSK:+CAMELLIA-128-CBC:+SHA256",
         None),
        ("TLS-DHE-PSK-WITH-CAMELLIA-256-CBC-SHA384",
         "+DHE-PSK:+CAMELLIA-256-CBC:+SHA384",
         None),
        ("TLS-PSK-WITH-CAMELLIA-128-CBC-SHA256",
         "+PSK:+CAMELLIA-128-CBC:+SHA256",
         None),
        ("TLS-PSK-WITH-CAMELLIA-256-CBC-SHA384",
         "+PSK:+CAMELLIA-256-CBC:+SHA384",
         None),
        ("TLS-RSA-PSK-WITH-CAMELLIA-256-CBC-SHA384",
         "+RSA-PSK:+CAMELLIA-256-CBC:+SHA384",
         None),
        ("TLS-RSA-PSK-WITH-CAMELLIA-128-CBC-SHA256",
         "+RSA-PSK:+CAMELLIA-128-CBC:+SHA256",
         None),
        ("TLS-PSK-WITH-AES-128-GCM-SHA256",
         "+PSK:+AES-128-GCM:+AEAD",
         None),
        ("TLS-PSK-WITH-AES-256-GCM-SHA384",
         "+PSK:+AES-256-GCM:+AEAD",
         None),
        ("TLS-DHE-PSK-WITH-AES-128-GCM-SHA256",
         "+DHE-PSK:+AES-128-GCM:+AEAD",
         None),
        ("TLS-DHE-PSK-WITH-AES-256-GCM-SHA384",
         "+DHE-PSK:+AES-256-GCM:+AEAD",
         None),
        ("TLS-PSK-WITH-AES-128-CCM",
         "+PSK:+AES-128-CCM:+AEAD",
         None),
        ("TLS-PSK-WITH-AES-256-CCM",
         "+PSK:+AES-256-CCM:+AEAD",
         None),
        ("TLS-DHE-PSK-WITH-AES-128-CCM",
         "+DHE-PSK:+AES-128-CCM:+AEAD",
         None),
        ("TLS-DHE-PSK-WITH-AES-256-CCM",
         "+DHE-PSK:+AES-256-CCM:+AEAD",
         None),
        ("TLS-PSK-WITH-AES-128-CCM-8",
         "+PSK:+AES-128-CCM-8:+AEAD",
         None),
        ("TLS-PSK-WITH-AES-256-CCM-8",
         "+PSK:+AES-256-CCM-8:+AEAD",
         None),
        ("TLS-DHE-PSK-WITH-AES-128-CCM-8",
         "+DHE-PSK:+AES-128-CCM-8:+AEAD",
         None),
        ("TLS-DHE-PSK-WITH-AES-256-CCM-8",
         "+DHE-PSK:+AES-256-CCM-8:+AEAD",
         None),
        ("TLS-RSA-PSK-WITH-CAMELLIA-128-GCM-SHA256",
         "+RSA-PSK:+CAMELLIA-128-GCM:+AEAD",
         None),
        ("TLS-RSA-PSK-WITH-CAMELLIA-256-GCM-SHA384",
         "+RSA-PSK:+CAMELLIA-256-GCM:+AEAD",
         None),
        ("TLS-PSK-WITH-CAMELLIA-128-GCM-SHA256",
         "+PSK:+CAMELLIA-128-GCM:+AEAD",
         None),
        ("TLS-PSK-WITH-CAMELLIA-256-GCM-SHA384",
         "+PSK:+CAMELLIA-256-GCM:+AEAD",
         None),
        ("TLS-DHE-PSK-WITH-CAMELLIA-128-GCM-SHA256",
         "+DHE-PSK:+CAMELLIA-128-GCM:+AEAD",
         None),
        ("TLS-DHE-PSK-WITH-CAMELLIA-256-GCM-SHA384",
         "+DHE-PSK:+CAMELLIA-256-GCM:+AEAD",
         None),
        ("TLS-RSA-PSK-WITH-AES-256-GCM-SHA384",
         "+RSA-PSK:+AES-256-GCM:+AEAD",
         None),
        ("TLS-RSA-PSK-WITH-AES-128-GCM-SHA256",
         "+RSA-PSK:+AES-128-GCM:+AEAD",
         None),
    ]

    for m, g_exp, o_exp in ciphers:

        if g_exp != None:
            g = translate_gnutls(m)
            assert_equal(g, g_exp)

        if o_exp != None:
            o = translate_ossl(m)
            assert_equal(o, o_exp)

test_all_common()
