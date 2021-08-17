#!/usr/bin/env python3
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

"""
This script confirms that the naming of all symbols and identifiers in Mbed TLS
are consistent with the house style and are also self-consistent. It only runs
on Linux and macOS since it depends on nm.

It contains two major Python classes, CodeParser and NameChecker. They both have
a comprehensive "run-all" function (comprehensive_parse() and perform_checks())
but the individual functions can also be used for specific needs.

CodeParser makes heavy use of regular expressions to parse the code, and is
dependent on the current code formatting. Many Python C parser libraries require
preprocessed C code, which means no macro parsing. Compiler tools are also not
very helpful when we want the exact location in the original source (which
becomes impossible when e.g. comments are stripped).

NameChecker performs the following checks:

- All exported and available symbols in the library object files, are explicitly
  declared in the header files. This uses the nm command.
- All macros, constants, and identifiers (function names, struct names, etc)
  follow the required regex pattern.
- Typo checking: All words that begin with MBED exist as macros or constants.

The script returns 0 on success, 1 on test failure, and 2 if there is a script
error. It must be run from Mbed TLS root.
"""

import argparse
import glob
import textwrap
import os
import sys
import traceback
import re
import shutil
import subprocess
import logging

# Naming patterns to check against. These are defined outside the NameCheck
# class for ease of modification.
MACRO_PATTERN = r"^(MBEDTLS|PSA)_[0-9A-Z_]*[0-9A-Z]$"
CONSTANTS_PATTERN = MACRO_PATTERN
IDENTIFIER_PATTERN = r"^(mbedtls|psa)_[0-9a-z_]*[0-9a-z]$"

class Match(): # pylint: disable=too-few-public-methods
    """
    A class representing a match, together with its found position.

    Fields:
    * filename: the file that the match was in.
    * line: the full line containing the match.
    * pos: a tuple of (line_no, start, end) positions on the file line where the
           match is.
    * name: the match itself.
    """
    def __init__(self, filename, line, pos, name):
        self.filename = filename
        self.line = line
        self.pos = pos
        self.name = name

    def __str__(self):
        """
        Return a formatted code listing representation of the erroneous line.
        """
        gutter = format(self.pos[0], "4d")
        underline = self.pos[1] * " " + (self.pos[2] - self.pos[1]) * "^"

        return (
            " {0} |\n".format(" " * len(gutter)) +
            " {0} | {1}".format(gutter, self.line) +
            " {0} | {1}\n".format(" " * len(gutter), underline)
        )

class Problem(): # pylint: disable=too-few-public-methods
    """
    A parent class representing a form of static analysis error.
    """
    # Class variable to control the quietness of all problems
    quiet = False
    def __init__(self):
        self.textwrapper = textwrap.TextWrapper()
        self.textwrapper.width = 80
        self.textwrapper.initial_indent = "    > "
        self.textwrapper.subsequent_indent = "      "

class SymbolNotInHeader(Problem): # pylint: disable=too-few-public-methods
    """
    A problem that occurs when an exported/available symbol in the object file
    is not explicitly declared in header files. Created with
    NameCheck.check_symbols_declared_in_header()

    Fields:
    * symbol_name: the name of the symbol.
    """
    def __init__(self, symbol_name):
        self.symbol_name = symbol_name
        Problem.__init__(self)

    def __str__(self):
        if self.quiet:
            return "{0}".format(self.symbol_name)

        return self.textwrapper.fill(
            "'{0}' was found as an available symbol in the output of nm, "
            "however it was not declared in any header files."
            .format(self.symbol_name))

class PatternMismatch(Problem): # pylint: disable=too-few-public-methods
    """
    A problem that occurs when something doesn't match the expected pattern.
    Created with NameCheck.check_match_pattern()

    Fields:
    * pattern: the expected regex pattern
    * match: the Match object in question
    """
    def __init__(self, pattern, match):
        self.pattern = pattern
        self.match = match
        Problem.__init__(self)

    def __str__(self):
        if self.quiet:
            return (
                "{0}:{1}:{2}"
                .format(self.match.filename, self.match.pos[0], self.match.name)
            )

        return self.textwrapper.fill(
            "{0}:{1}: '{2}' does not match the required pattern '{3}'."
            .format(
                self.match.filename,
                self.match.pos[0],
                self.match.name,
                self.pattern
            )
        ) + "\n" + str(self.match)

class Typo(Problem): # pylint: disable=too-few-public-methods
    """
    A problem that occurs when a word using MBED doesn't appear to be defined as
    constants nor enum values. Created with NameCheck.check_for_typos()

    Fields:
    * match: the Match object of the MBED name in question.
    """
    def __init__(self, match):
        self.match = match
        Problem.__init__(self)

    def __str__(self):
        if self.quiet:
            return (
                "{0}:{1}:{2}"
                .format(self.match.filename, self.match.pos[0], self.match.name)
            )

        return self.textwrapper.fill(
            "{0}:{1}: '{2}' looks like a typo. It was not found in any "
            "macros or any enums. If this is not a typo, put "
            "//no-check-names after it."
            .format(self.match.filename, self.match.pos[0], self.match.name)
        ) + "\n" + str(self.match)

class CodeParser():
    """
    Class for retrieving files and parsing the code. This can be used
    independently of the checks that NameChecker performs, for example for
    list_internal_identifiers.py.
    """
    def __init__(self, log):
        self.log = log
        self.check_repo_path()

        # Memo for storing "glob expression": set(filepaths)
        self.files = {}

        # Globally excluded filenames
        self.excluded_files = ["**/bn_mul", "**/compat-2.x.h"]

    @staticmethod
    def check_repo_path():
        """
        Check that the current working directory is the project root, and throw
        an exception if not.
        """
        if not all(os.path.isdir(d) for d in ["include", "library", "tests"]):
            raise Exception("This script must be run from Mbed TLS root")

    def comprehensive_parse(self):
        """
        Comprehensive ("default") function to call each parsing function and
        retrieve various elements of the code, together with the source location.

        Returns a dict of parsed item key to the corresponding List of Matches.
        """
        self.log.info("Parsing source code...")
        self.log.debug(
            "The following files are excluded from the search: {}"
            .format(str(self.excluded_files))
        )

        all_macros = self.parse_macros([
            "include/mbedtls/*.h",
            "include/psa/*.h",
            "library/*.h",
            "tests/include/test/drivers/*.h",
            "3rdparty/everest/include/everest/everest.h",
            "3rdparty/everest/include/everest/x25519.h"
        ])
        enum_consts = self.parse_enum_consts([
            "include/mbedtls/*.h",
            "library/*.h",
            "3rdparty/everest/include/everest/everest.h",
            "3rdparty/everest/include/everest/x25519.h"
        ])
        identifiers = self.parse_identifiers([
            "include/mbedtls/*.h",
            "include/psa/*.h",
            "library/*.h",
            "3rdparty/everest/include/everest/everest.h",
            "3rdparty/everest/include/everest/x25519.h"
        ])
        mbed_words = self.parse_mbed_words([
            "include/mbedtls/*.h",
            "include/psa/*.h",
            "library/*.h",
            "3rdparty/everest/include/everest/everest.h",
            "3rdparty/everest/include/everest/x25519.h",
            "library/*.c",
            "3rdparty/everest/library/everest.c",
            "3rdparty/everest/library/x25519.c"
        ])
        symbols = self.parse_symbols()

        # Remove identifier macros like mbedtls_printf or mbedtls_calloc
        identifiers_justname = [x.name for x in identifiers]
        actual_macros = []
        for macro in all_macros:
            if macro.name not in identifiers_justname:
                actual_macros.append(macro)

        self.log.debug("Found:")
        # Aligns the counts on the assumption that none exceeds 4 digits
        self.log.debug("  {:4} Total Macros".format(len(all_macros)))
        self.log.debug("  {:4} Non-identifier Macros".format(len(actual_macros)))
        self.log.debug("  {:4} Enum Constants".format(len(enum_consts)))
        self.log.debug("  {:4} Identifiers".format(len(identifiers)))
        self.log.debug("  {:4} Exported Symbols".format(len(symbols)))
        return {
            "macros": actual_macros,
            "enum_consts": enum_consts,
            "identifiers": identifiers,
            "symbols": symbols,
            "mbed_words": mbed_words
        }

    def get_files(self, include_wildcards, exclude_wildcards):
        """
        Get all files that match any of the UNIX-style wildcards. While the
        check_names script is designed only for use on UNIX/macOS (due to nm),
        this function alone would work fine on Windows even with forward slashes
        in the wildcard.

        Args:
        * include_wildcards: a List of shell-style wildcards to match filepaths.
        * exclude_wildcards: a List of shell-style wildcards to exclude.

        Returns a List of relative filepaths.
        """
        accumulator = set()

        # exclude_wildcards may be None. Also, consider the global exclusions.
        exclude_wildcards = (exclude_wildcards or []) + self.excluded_files

        # Internal function to hit the memoisation cache or add to it the result
        # of a glob operation. Used both for inclusion and exclusion since the
        # only difference between them is whether they perform set union or
        # difference on the return value of this function.
        def hit_cache(wildcard):
            if wildcard not in self.files:
                self.files[wildcard] = set(glob.glob(wildcard, recursive=True))
            return self.files[wildcard]

        for include_wildcard in include_wildcards:
            accumulator = accumulator.union(hit_cache(include_wildcard))

        for exclude_wildcard in exclude_wildcards:
            accumulator = accumulator.difference(hit_cache(exclude_wildcard))

        return list(accumulator)

    def parse_macros(self, include, exclude=None):
        """
        Parse all macros defined by #define preprocessor directives.

        Args:
        * include: A List of glob expressions to look for files through.
        * exclude: A List of glob expressions for excluding files.

        Returns a List of Match objects for the found macros.
        """
        macro_regex = re.compile(r"# *define +(?P<macro>\w+)")
        exclusions = (
            "asm", "inline", "EMIT", "_CRT_SECURE_NO_DEPRECATE", "MULADDC_"
        )

        files = self.get_files(include, exclude)
        self.log.debug("Looking for macros in {} files".format(len(files)))

        macros = []
        for header_file in files:
            with open(header_file, "r", encoding="utf-8") as header:
                for line_no, line in enumerate(header):
                    for macro in macro_regex.finditer(line):
                        if macro.group("macro").startswith(exclusions):
                            continue

                        macros.append(Match(
                            header_file,
                            line,
                            (line_no, macro.start(), macro.end()),
                            macro.group("macro")))

        return macros

    def parse_mbed_words(self, include, exclude=None):
        """
        Parse all words in the file that begin with MBED, in and out of macros,
        comments, anything.

        Args:
        * include: A List of glob expressions to look for files through.
        * exclude: A List of glob expressions for excluding files.

        Returns a List of Match objects for words beginning with MBED.
        """
        # Typos of TLS are common, hence the broader check below than MBEDTLS.
        mbed_regex = re.compile(r"\bMBED.+?_[A-Z0-9_]*")
        exclusions = re.compile(r"// *no-check-names|#error")

        files = self.get_files(include, exclude)
        self.log.debug("Looking for MBED words in {} files".format(len(files)))

        mbed_words = []
        for filename in files:
            with open(filename, "r", encoding="utf-8") as fp:
                for line_no, line in enumerate(fp):
                    if exclusions.search(line):
                        continue

                    for name in mbed_regex.finditer(line):
                        mbed_words.append(Match(
                            filename,
                            line,
                            (line_no, name.start(), name.end()),
                            name.group(0)
                            ))

        return mbed_words

    def parse_enum_consts(self, include, exclude=None):
        """
        Parse all enum value constants that are declared.

        Args:
        * include: A List of glob expressions to look for files through.
        * exclude: A List of glob expressions for excluding files.

        Returns a List of Match objects for the findings.
        """
        files = self.get_files(include, exclude)
        self.log.debug("Looking for enum consts in {} files".format(len(files)))

        enum_consts = []
        for header_file in files:
            # Emulate a finite state machine to parse enum declarations.
            # 0 = not in enum
            # 1 = inside enum
            # 2 = almost inside enum
            state = 0
            with open(header_file, "r", encoding="utf-8") as header:
                for line_no, line in enumerate(header):
                    # Match typedefs and brackets only when they are at the
                    # beginning of the line -- if they are indented, they might
                    # be sub-structures within structs, etc.
                    if state == 0 and re.search(r"^(typedef +)?enum +{", line):
                        state = 1
                    elif state == 0 and re.search(r"^(typedef +)?enum", line):
                        state = 2
                    elif state == 2 and re.search(r"^{", line):
                        state = 1
                    elif state == 1 and re.search(r"^}", line):
                        state = 0
                    elif state == 1 and not re.search(r"^ *#", line):
                        enum_const = re.search(r"^ *(?P<enum_const>\w+)", line)
                        if not enum_const:
                            continue

                        enum_consts.append(Match(
                            header_file,
                            line,
                            (line_no, enum_const.start(), enum_const.end()),
                            enum_const.group("enum_const")))

        return enum_consts

    def parse_identifiers(self, include, exclude=None):
        """
        Parse all lines of a header where a function/enum/struct/union/typedef
        identifier is declared, based on some heuristics. Highly dependent on
        formatting style.

        Args:
        * include: A List of glob expressions to look for files through.
        * exclude: A List of glob expressions for excluding files.

        Returns a List of Match objects with identifiers.
        """
        identifier_regex = re.compile(
            # Match " something(a" or " *something(a". Functions.
            # Assumptions:
            # - function definition from return type to one of its arguments is
            #   all on one line
            # - function definition line only contains alphanumeric, asterisk,
            #   underscore, and open bracket
            r".* \**(\w+) *\( *\w|"
            # Match "(*something)(".
            r".*\( *\* *(\w+) *\) *\(|"
            # Match names of named data structures.
            r"(?:typedef +)?(?:struct|union|enum) +(\w+)(?: *{)?$|"
            # Match names of typedef instances, after closing bracket.
            r"}? *(\w+)[;[].*"
        )
        exclusion_lines = re.compile(
            r"^("
                r"extern +\"C\"|"
                r"(typedef +)?(struct|union|enum)( *{)?$|"
                r"} *;?$|"
                r"$|"
                r"//|"
                r"#"
            r")"
        )

        files = self.get_files(include, exclude)
        self.log.debug("Looking for identifiers in {} files".format(len(files)))

        identifiers = []
        for header_file in files:
            with open(header_file, "r", encoding="utf-8") as header:
                in_block_comment = False
                # The previous line variable is used for concatenating lines
                # when identifiers are formatted and spread across multiple.
                previous_line = ""

                for line_no, line in enumerate(header):
                    # Skip parsing this line if a block comment ends on it,
                    # but don't skip if it has just started -- there is a chance
                    # it ends on the same line.
                    if re.search(r"/\*", line):
                        in_block_comment = not in_block_comment
                    if re.search(r"\*/", line):
                        in_block_comment = not in_block_comment
                        continue

                    if in_block_comment:
                        previous_line = ""
                        continue

                    if exclusion_lines.search(line):
                        previous_line = ""
                        continue

                    # If the line contains only space-separated alphanumeric
                    # characters (or underscore, asterisk, or, open bracket),
                    # and nothing else, high chance it's a declaration that
                    # continues on the next line
                    if re.search(r"^([\w\*\(]+\s+)+$", line):
                        previous_line += line
                        continue

                    # If previous line seemed to start an unfinished declaration
                    # (as above), concat and treat them as one.
                    if previous_line:
                        line = previous_line.strip() + " " + line.strip() + "\n"
                        previous_line = ""

                    # Skip parsing if line has a space in front = heuristic to
                    # skip function argument lines (highly subject to formatting
                    # changes)
                    if line[0] == " ":
                        continue

                    identifier = identifier_regex.search(line)

                    if not identifier:
                        continue

                    # Find the group that matched, and append it
                    for group in identifier.groups():
                        if not group:
                            continue

                        identifiers.append(Match(
                            header_file,
                            line,
                            (line_no, identifier.start(), identifier.end()),
                            group))

        return identifiers

    def parse_symbols(self):
        """
        Compile the Mbed TLS libraries, and parse the TLS, Crypto, and x509
        object files using nm to retrieve the list of referenced symbols.
        Exceptions thrown here are rethrown because they would be critical
        errors that void several tests, and thus needs to halt the program. This
        is explicitly done for clarity.

        Returns a List of unique symbols defined and used in the libraries.
        """
        self.log.info("Compiling...")
        symbols = []

        # Back up the config and atomically compile with the full configratuion.
        shutil.copy(
            "include/mbedtls/mbedtls_config.h",
            "include/mbedtls/mbedtls_config.h.bak"
        )
        try:
            # Use check=True in all subprocess calls so that failures are raised
            # as exceptions and logged.
            subprocess.run(
                ["python3", "scripts/config.py", "full"],
                universal_newlines=True,
                check=True
            )
            my_environment = os.environ.copy()
            my_environment["CFLAGS"] = "-fno-asynchronous-unwind-tables"
            subprocess.run(
                ["make", "clean", "lib"],
                env=my_environment,
                universal_newlines=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=True
            )

            # Perform object file analysis using nm
            symbols = self.parse_symbols_from_nm([
                "library/libmbedcrypto.a",
                "library/libmbedtls.a",
                "library/libmbedx509.a"
            ])

            subprocess.run(
                ["make", "clean"],
                universal_newlines=True,
                check=True
            )
        except subprocess.CalledProcessError as error:
            self.log.debug(error.output)
            raise error
        finally:
            # Put back the original config regardless of there being errors.
            # Works also for keyboard interrupts.
            shutil.move(
                "include/mbedtls/mbedtls_config.h.bak",
                "include/mbedtls/mbedtls_config.h"
            )

        return symbols

    def parse_symbols_from_nm(self, object_files):
        """
        Run nm to retrieve the list of referenced symbols in each object file.
        Does not return the position data since it is of no use.

        Args:
        * object_files: a List of compiled object filepaths to search through.

        Returns a List of unique symbols defined and used in any of the object
        files.
        """
        nm_undefined_regex = re.compile(r"^\S+: +U |^$|^\S+:$")
        nm_valid_regex = re.compile(r"^\S+( [0-9A-Fa-f]+)* . _*(?P<symbol>\w+)")
        exclusions = ("FStar", "Hacl")

        symbols = []

        # Gather all outputs of nm
        nm_output = ""
        for lib in object_files:
            nm_output += subprocess.run(
                ["nm", "-og", lib],
                universal_newlines=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=True
            ).stdout

        for line in nm_output.splitlines():
            if not nm_undefined_regex.search(line):
                symbol = nm_valid_regex.search(line)
                if (symbol and not symbol.group("symbol").startswith(exclusions)):
                    symbols.append(symbol.group("symbol"))
                else:
                    self.log.error(line)

        return symbols

class NameChecker():
    """
    Representation of the core name checking operation performed by this script.
    """
    def __init__(self, parse_result, log):
        self.parse_result = parse_result
        self.log = log

    def perform_checks(self, quiet=False):
        """
        A comprehensive checker that performs each check in order, and outputs
        a final verdict.

        Args:
        * quiet: whether to hide detailed problem explanation.
        """
        self.log.info("=============")
        Problem.quiet = quiet
        problems = 0
        problems += self.check_symbols_declared_in_header()

        pattern_checks = [
            ("macros", MACRO_PATTERN),
            ("enum_consts", CONSTANTS_PATTERN),
            ("identifiers", IDENTIFIER_PATTERN)
        ]
        for group, check_pattern in pattern_checks:
            problems += self.check_match_pattern(group, check_pattern)

        problems += self.check_for_typos()

        self.log.info("=============")
        if problems > 0:
            self.log.info("FAIL: {0} problem(s) to fix".format(str(problems)))
            if quiet:
                self.log.info("Remove --quiet to see explanations.")
            else:
                self.log.info("Use --quiet for minimal output.")
            return 1
        else:
            self.log.info("PASS")
            return 0

    def check_symbols_declared_in_header(self):
        """
        Perform a check that all detected symbols in the library object files
        are properly declared in headers.
        Assumes parse_names_in_source() was called before this.

        Returns the number of problems that need fixing.
        """
        problems = []

        for symbol in self.parse_result["symbols"]:
            found_symbol_declared = False
            for identifier_match in self.parse_result["identifiers"]:
                if symbol == identifier_match.name:
                    found_symbol_declared = True
                    break

            if not found_symbol_declared:
                problems.append(SymbolNotInHeader(symbol))

        self.output_check_result("All symbols in header", problems)
        return len(problems)

    def check_match_pattern(self, group_to_check, check_pattern):
        """
        Perform a check that all items of a group conform to a regex pattern.
        Assumes parse_names_in_source() was called before this.

        Args:
        * group_to_check: string key to index into self.parse_result.
        * check_pattern: the regex to check against.

        Returns the number of problems that need fixing.
        """
        problems = []

        for item_match in self.parse_result[group_to_check]:
            if not re.search(check_pattern, item_match.name):
                problems.append(PatternMismatch(check_pattern, item_match))
            # Double underscore should not be used for names
            if re.search(r".*__.*", item_match.name):
                problems.append(PatternMismatch("double underscore", item_match))

        self.output_check_result(
            "Naming patterns of {}".format(group_to_check),
            problems)
        return len(problems)

    def check_for_typos(self):
        """
        Perform a check that all words in the soure code beginning with MBED are
        either defined as macros, or as enum constants.
        Assumes parse_names_in_source() was called before this.

        Returns the number of problems that need fixing.
        """
        problems = []

        # Set comprehension, equivalent to a list comprehension wrapped by set()
        all_caps_names = {
            match.name
            for match
            in self.parse_result["macros"] + self.parse_result["enum_consts"]}
        typo_exclusion = re.compile(r"XXX|__|_$|^MBEDTLS_.*CONFIG_FILE$")

        for name_match in self.parse_result["mbed_words"]:
            found = name_match.name in all_caps_names

            # Since MBEDTLS_PSA_ACCEL_XXX defines are defined by the
            # PSA driver, they will not exist as macros. However, they
            # should still be checked for typos using the equivalent
            # BUILTINs that exist.
            if "MBEDTLS_PSA_ACCEL_" in name_match.name:
                found = name_match.name.replace(
                    "MBEDTLS_PSA_ACCEL_",
                    "MBEDTLS_PSA_BUILTIN_") in all_caps_names

            if not found and not typo_exclusion.search(name_match.name):
                problems.append(Typo(name_match))

        self.output_check_result("Likely typos", problems)
        return len(problems)

    def output_check_result(self, name, problems):
        """
        Write out the PASS/FAIL status of a performed check depending on whether
        there were problems.

        Args:
        * name: the name of the test
        * problems: a List of encountered Problems
        """
        if problems:
            self.log.info("{}: FAIL\n".format(name))
            for problem in problems:
                self.log.warning(str(problem))
        else:
            self.log.info("{}: PASS".format(name))

def main():
    """
    Perform argument parsing, and create an instance of CodeParser and
    NameChecker to begin the core operation.
    """
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "This script confirms that the naming of all symbols and identifiers "
            "in Mbed TLS are consistent with the house style and are also "
            "self-consistent.\n\n"
            "Expected to be run from the MbedTLS root directory.")
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="show parse results"
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="hide unnecessary text, explanations, and highlighs"
    )

    args = parser.parse_args()

    # Configure the global logger, which is then passed to the classes below
    log = logging.getLogger()
    log.setLevel(logging.DEBUG if args.verbose else logging.INFO)
    log.addHandler(logging.StreamHandler())

    try:
        code_parser = CodeParser(log)
        parse_result = code_parser.comprehensive_parse()
    except Exception: # pylint: disable=broad-except
        traceback.print_exc()
        sys.exit(2)

    name_checker = NameChecker(parse_result, log)
    return_code = name_checker.perform_checks(quiet=args.quiet)

    sys.exit(return_code)

if __name__ == "__main__":
    main()
