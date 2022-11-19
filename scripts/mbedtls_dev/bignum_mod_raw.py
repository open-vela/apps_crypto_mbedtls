"""Framework classes for generation of bignum mod_raw test cases."""
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

from typing import Dict, List

from . import test_data_generation
from . import bignum_common

class BignumModRawTarget(test_data_generation.BaseTarget):
    #pylint: disable=abstract-method, too-few-public-methods
    """Target for bignum mod_raw test case generation."""
    target_basename = 'test_suite_bignum_mod_raw.generated'

# BEGIN MERGE SLOT 1

# END MERGE SLOT 1

# BEGIN MERGE SLOT 2

# END MERGE SLOT 2

# BEGIN MERGE SLOT 3

# END MERGE SLOT 3

# BEGIN MERGE SLOT 4

# END MERGE SLOT 4

# BEGIN MERGE SLOT 5

# END MERGE SLOT 5

# BEGIN MERGE SLOT 6

# END MERGE SLOT 6

# BEGIN MERGE SLOT 7
class BignumModRawConvertToMont(bignum_common.ModOperationCommon,
                                BignumModRawTarget):
    """ Test cases for mpi_mod_raw_to_mont_rep(). """

    test_function = "mpi_mod_raw_to_mont_rep"
    test_name = "Convert into Mont: "
    symbol = "R *"
    input_style = "arch_split"
    arity = 1

    moduli = ["b",
              "fd",
              "eeff99aa37",
              "eeff99aa11",
              "800000000005",
              "7fffffffffffffff",
              "80fe000a10000001",
              "25a55a46e5da99c71c7",
              "1058ad82120c3a10196bb36229c1",
              "7e35b84cb19ea5bc57ec37f5e431462fa962d98c1e63738d4657f"
              "18ad6532e6adc3eafe67f1e5fa262af94cee8d3e7268593942a2a"
              "98df75154f8c914a282f8b",
              "8335616aed761f1f7f44e6bd49e807b82e3bf2bf11bfa63",
              "ffcece570f2f991013f26dd5b03c4c5b65f97be5905f36cb4664f"
              "2c78ff80aa8135a4aaf57ccb8a0aca2f394909a74cef1ef6758a6"
              "4d11e2c149c393659d124bfc94196f0ce88f7d7d567efa5a649e2"
              "deefaa6e10fdc3deac60d606bf63fc540ac95294347031aefd73d"
              "6a9ee10188aaeb7a90d920894553cb196881691cadc51808715a0"
              "7e8b24fcb1a63df047c7cdf084dd177ba368c806f3d51ddb5d389"
              "8c863e687ecaf7d649a57a46264a582f94d3c8f2edaf59f77a7f6"
              "bdaf83c991e8f06abe220ec8507386fce8c3da84c6c3903ab8f3a"
              "d4630a204196a7dbcbd9bcca4e40ec5cc5c09938d49f5e1e6181d"
              "b8896f33bb12e6ef73f12ec5c5ea7a8a337"
              ]

    input_values = ["0",
                    "1",
                    "97",
                    "f5",
                    "6f5c3",
                    "745bfe50f7",
                    "ffa1f9924123",
                    "334a8b983c79bd",
                    "5b84f632b58f3461",
                    "19acd15bc38008e1",
                    "ffffffffffffffff",
                    "54ce6a6bb8247fa0427cfc75a6b0599",
                    "fecafe8eca052f154ce6a6bb8247fa019558bfeecce9bb9",
                    "a87d7a56fa4bfdc7da42ef798b9cf6843d4c54794698cb14d72"
                    "851dec9586a319f4bb6d5695acbd7c92e7a42a5ede6972adcbc"
                    "f68425265887f2d721f462b7f1b91531bac29fa648facb8e3c6"
                    "1bd5ae42d5a59ba1c89a95897bfe541a8ce1d633b98f379c481"
                    "6f25e21f6ac49286b261adb4b78274fe5f61c187581f213e84b"
                    "2a821e341ef956ecd5de89e6c1a35418cd74a549379d2d4594a"
                    "577543147f8e35b3514e62cf3e89d1156cdc91ab5f4c928fbd6"
                    "9148c35df5962fed381f4d8a62852a36823d5425f7487c13a12"
                    "523473fb823aa9d6ea5f42e794e15f2c1a8785cf6b7d51a4617"
                    "947fb3baf674f74a673cf1d38126983a19ed52c7439fab42c2185"
                    ]

    def result(self) -> List[str]:
        result = (self.int_a * self.r) % self.int_n
        return [self.format_result(result)]


class BignumModRawConvertFromMont(BignumModRawConvertToMont):
    """ Test cases for mpi_mod_raw_from_mont_rep(). """
    count = 0
    test_function = "mpi_mod_raw_from_mont_rep"
    test_name = "Convert from Mont: "
    symbol = "1/R *"

    input_values = ["0",
                    "1",
                    "3ca",
                    "539ed428",
                    "7dfe5c6beb35a2d6",
                    "dca8de1c2adfc6d7aafb9b48e",
                    "a7d17b6c4be72f3d5c16bf9c1af6fc933",
                    "2fec97beec546f9553142ed52f147845463f579",
                    "378dc83b8bc5a7b62cba495af4919578dce6d4f175cadc4f",
                    "b6415f2a1a8e48a518345db11f56db3829c8f2c6415ab4a395a"
                    "b3ac2ea4cbef4af86eb18a84eb6ded4c6ecbfc4b59c2879a675"
                    "487f687adea9d197a84a5242a5cf6125ce19a6ad2e7341f1c57"
                    "d43ea4f4c852a51cb63dabcd1c9de2b827a3146a3d175b35bea"
                    "41ae75d2a286a3e9d43623152ac513dcdea1d72a7da846a8ab3"
                    "58d9be4926c79cfb287cf1cf25b689de3b912176be5dcaf4d4c"
                    "6e7cb839a4a3243a6c47c1e2c99d65c59d6fa3672575c2f1ca8"
                    "de6a32e854ec9d8ec635c96af7679fce26d7d159e4a9da3bd74"
                    "e1272c376cd926d74fe3fb164a5935cff3d5cdb92b35fe2cea32"
                    "138a7e6bfbc319ebd1725dacb9a359cbf693f2ecb785efb9d627"
                   ]

    def result(self) -> List[str]:
        result = (self.int_a * self.r_inv) % self.int_n
        return [self.format_result(result)]


# END MERGE SLOT 7

# BEGIN MERGE SLOT 8

# END MERGE SLOT 8

# BEGIN MERGE SLOT 9

# END MERGE SLOT 9

# BEGIN MERGE SLOT 10

# END MERGE SLOT 10
