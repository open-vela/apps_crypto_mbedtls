#!/usr/bin/env python3
"""Generate test data for bignum functions.

With no arguments, generate all test data. With non-option arguments,
generate only the specified files.

Class structure:

Child classes of test_generation.BaseTarget (file Targets) represent a target
file. These indicate where test cases will be written to, for all subclasses of
this Target. Multiple Target classes should not reuse a `target_basename`.

Each subclass derived from a file Target can either be:
  - A concrete class, representing a test function, which generates test cases.
  - An abstract class containing shared methods and attributes, not associated
        with a test function. An example is BignumOperation, which provides
        common features used for bignum binary operations.

Both concrete and abstract subclasses can be derived from, to implement
additional test cases (see BignumCmp and BignumCmpAbs for examples of deriving
from abstract and concrete classes).


Adding test case generation for a function:

A subclass representing the test function should be added, deriving from a
file Target such as BignumTarget. This test class must set/implement the
following:
  - test_function: the function name from the associated .function file.
  - test_name: a descriptive name or brief summary to refer to the test
        function.
  - arguments(): a method to generate the list of arguments required for the
        test_function.
  - generate_function_test(): a method to generate TestCases for the function.
        This should create instances of the class with required input data, and
        call `.create_test_case()` to yield the TestCase.

Additional details and other attributes/methods are given in the documentation
of BaseTarget in test_generation.py.
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

import itertools
import sys

from abc import ABCMeta, abstractmethod
from typing import Callable, Dict, Iterable, Iterator, List, Tuple, TypeVar, cast

import scripts_path # pylint: disable=unused-import
from mbedtls_dev import test_case
from mbedtls_dev import test_generation

T = TypeVar('T') #pylint: disable=invalid-name

def hex_to_int(val: str) -> int:
    return int(val, 16) if val else 0

def quote_str(val) -> str:
    return "\"{}\"".format(val)


class BignumTarget(test_generation.BaseTarget, metaclass=ABCMeta):
    #pylint: disable=abstract-method
    """Target for bignum (mpi) test case generation."""
    target_basename = 'test_suite_mpi.generated'


class BignumOperation(BignumTarget, metaclass=ABCMeta):
    """Common features for bignum binary operations.

    This adds functionality common in binary operation tests. This includes
    generation of case descriptions, using descriptions of values and symbols
    to represent the operation or result.

    Attributes:
        symbol: Symbol used for the operation in case description.
        input_values: List of values to use as test case inputs. These are
            combined to produce pairs of values.
        input_cases: List of tuples containing pairs of test case inputs. This
            can be used to implement specific pairs of inputs.
    """
    symbol = ""
    input_values = [
        "", "0", "7b", "-7b",
        "0000000000000000123", "-0000000000000000123",
        "1230000000000000000", "-1230000000000000000"
    ] # type: List[str]
    input_cases = cast(List[Tuple[str, str]], []) # type: List[Tuple[str, str]]

    def __init__(self, val_l: str, val_r: str) -> None:
        self.arg_l = val_l
        self.arg_r = val_r
        self.int_l = hex_to_int(val_l)
        self.int_r = hex_to_int(val_r)

    def arguments(self) -> List[str]:
        return [quote_str(self.arg_l), quote_str(self.arg_r), self.result()]

    def description(self) -> str:
        """Generate a description for the test case.

        If not set, case_description uses the form A `symbol` B, where symbol
        is used to represent the operation. Descriptions of each value are
        generated to provide some context to the test case.
        """
        if not self.case_description:
            self.case_description = "{} {} {}".format(
                self.value_description(self.arg_l),
                self.symbol,
                self.value_description(self.arg_r)
            )
        return super().description()

    @abstractmethod
    def result(self) -> str:
        """Get the result of the operation.

        This could be calculated during initialization and stored as `_result`
        and then returned, or calculated when the method is called.
        """
        raise NotImplementedError

    @staticmethod
    def value_description(val) -> str:
        """Generate a description of the argument val.

        This produces a simple description of the value, which is used in test
        case naming to add context.
        """
        if val == "":
            return "0 (null)"
        if val == "0":
            return "0 (1 limb)"

        if val[0] == "-":
            tmp = "negative"
            val = val[1:]
        else:
            tmp = "positive"
        if val[0] == "0":
            tmp += " with leading zero limb"
        elif len(val) > 10:
            tmp = "large " + tmp
        return tmp

    @classmethod
    def get_value_pairs(cls) -> Iterator[Tuple[str, str]]:
        """Generator to yield pairs of inputs.

        Combinations are first generated from all input values, and then
        specific cases provided.
        """
        yield from cast(
            Iterator[Tuple[str, str]],
            itertools.combinations_with_replacement(cls.input_values, 2)
        )
        yield from cls.input_cases

    @classmethod
    def generate_function_tests(cls) -> Iterator[test_case.TestCase]:
        for l_value, r_value in cls.get_value_pairs():
            cur_op = cls(l_value, r_value)
            yield cur_op.create_test_case()


class BignumCmp(BignumOperation):
    """Test cases for bignum value comparison."""
    count = 0
    test_function = "mbedtls_mpi_cmp_mpi"
    test_name = "MPI compare"
    input_cases = [
        ("-2", "-3"),
        ("-2", "-2"),
        ("2b4", "2b5"),
        ("2b5", "2b6")
        ]

    def __init__(self, val_l, val_r) -> None:
        super().__init__(val_l, val_r)
        self._result = int(self.int_l > self.int_r) - int(self.int_l < self.int_r)
        self.symbol = ["<", "==", ">"][self._result + 1]

    def result(self) -> str:
        return str(self._result)


class BignumCmpAbs(BignumCmp):
    """Test cases for absolute bignum value comparison."""
    count = 0
    test_function = "mbedtls_mpi_cmp_abs"
    test_name = "MPI compare (abs)"

    def __init__(self, val_l, val_r) -> None:
        super().__init__(val_l.strip("-"), val_r.strip("-"))


class BignumAdd(BignumOperation):
    """Test cases for bignum value addition."""
    count = 0
    test_function = "mbedtls_mpi_add_mpi"
    test_name = "MPI add"
    input_cases = cast(
        List[Tuple[str, str]],
        list(itertools.combinations_with_replacement(
            [
                "1c67967269c6", "9cde3",
                "-1c67967269c6", "-9cde3",
            ], 2
        ))
    )

    def __init__(self, val_l, val_r) -> None:
        super().__init__(val_l, val_r)
        self.symbol = "+"

    def result(self) -> str:
        return quote_str(hex(self.int_l + self.int_r).replace("0x", "", 1))


class BignumTestGenerator(test_generation.TestGenerator):
    """Test generator subclass, for bignum file Targets."""
    TARGETS = {
        subclass.target_basename: subclass.generate_tests for subclass in
        test_generation.BaseTarget.__subclasses__()
    } # type: Dict[str, Callable[[], Iterable[test_case.TestCase]]]

if __name__ == '__main__':
    test_generation.main(sys.argv[1:], BignumTestGenerator)
