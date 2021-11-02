"""Library for generating Mbed TLS test data.
"""

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

import binascii
import os
import sys
from typing import Iterable, List, Optional

from mbedtls_dev import typing_util

def hex_string(data: bytes) -> str:
    return '"' + binascii.hexlify(data).decode('ascii') + '"'


class MissingDescription(Exception):
    pass

class MissingFunction(Exception):
    pass

class TestCase:
    """An Mbed TLS test case."""

    def __init__(self, description: Optional[str] = None):
        self.comments = [] #type: List[str]
        self.description = description #type: Optional[str]
        self.dependencies = [] #type: List[str]
        self.function = None #type: Optional[str]
        self.arguments = [] #type: List[str]

    def add_comment(self, *lines: str) -> None:
        self.comments += lines

    def set_description(self, description: str) -> None:
        self.description = description

    def set_dependencies(self, dependencies: List[str]) -> None:
        self.dependencies = dependencies

    def set_function(self, function: str) -> None:
        self.function = function

    def set_arguments(self, arguments: List[str]) -> None:
        self.arguments = arguments

    def check_completeness(self) -> None:
        if self.description is None:
            raise MissingDescription
        if self.function is None:
            raise MissingFunction

    def write(self, out: typing_util.Writable) -> None:
        """Write the .data file paragraph for this test case.

        The output starts and ends with a single newline character. If the
        surrounding code writes lines (consisting of non-newline characters
        and a final newline), you will end up with a blank line before, but
        not after the test case.
        """
        self.check_completeness()
        assert self.description is not None # guide mypy
        assert self.function is not None # guide mypy
        out.write('\n')
        for line in self.comments:
            out.write('# ' + line + '\n')
        out.write(self.description + '\n')
        if self.dependencies:
            out.write('depends_on:' + ':'.join(self.dependencies) + '\n')
        out.write(self.function + ':' + ':'.join(self.arguments))

def write_data_file(filename: str,
                    test_cases: Iterable[TestCase],
                    caller: Optional[str] = None) -> None:
    """Write the test cases to the specified file.

    If the file already exists, it is overwritten.
    """
    if caller is None:
        caller = os.path.basename(sys.argv[0])
    with open(filename, 'w') as out:
        out.write('# Automatically generated by {}. Do not edit!\n'
                  .format(caller))
        for tc in test_cases:
            tc.write(out)
        out.write('\n# End of automatically generated file.\n')
