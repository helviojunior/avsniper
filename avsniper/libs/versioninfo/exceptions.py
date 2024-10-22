# Copyright 2022 Malwarology LLC
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.
"""Custom exceptions."""


class TruncatedInputError(Exception):
    """The size of actual data input is less than the size of the structure shown in the first header."""

    pass


class BadHeaderError(Exception):
    """The header is not parsable and potentially corrupted."""

    pass


class CorruptedStringError(Exception):
    """A String appears to have a premature null terminator indicating data corruption."""

    pass


class ZeroStompingError(Exception):
    """A part of the structure may have been overwritten with zeros."""

    pass
