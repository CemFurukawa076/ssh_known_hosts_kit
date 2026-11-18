"""Parsing helpers for OpenSSH ``known_hosts`` files.

The package deliberately exposes a very small surface: one dataclass and one
parse function.  Anything more elaborate (line numbers, comments, options)
would have to be invented, and invented requirements are how parsers grow
bugs.
"""

from .core import KnownHost, parse_known_host

__all__ = ["KnownHost", "parse_known_host"]
