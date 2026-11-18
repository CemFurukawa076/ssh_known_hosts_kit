"""Core parser for a single ``known_hosts`` line.

The OpenSSH format is deceptively small.  A line is either blank, a comment,
or a space separated record::

    [marker] hostnames keytype base64key [comment]

where ``marker`` is one of ``@cert-authority`` or ``@revoked``.  Hostnames may
be a comma separated list, and any single hostname may be hashed as
``|1|<base64 salt>|<base64 sha1>``.  We keep hashed hostnames verbatim rather
than trying to reverse them: the hash is salted and one way, so returning the
literal token is the only honest answer.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from typing import Optional, Tuple


#: Markers defined by OpenSSH.  Kept as a frozenset so membership tests are
#: cheap and the value cannot be mutated by callers.
MARKERS = frozenset({"@cert-authority", "@revoked"})


@dataclass(frozen=True)
class KnownHost:
    """A parsed ``known_hosts`` record.

    Attributes:
        hosts: The hostname field exactly as it appeared, including any
            comma separated entries and any ``|1|...`` hashed tokens.
        key_type: The SSH key algorithm, e.g. ``ssh-ed25519``.
        key: The base64 key material, decoded to bytes.  We decode here
            because every consumer eventually wants bytes, and doing it once
            keeps the failure mode (bad base64) in one place.
        marker: ``None`` for ordinary records, otherwise one of the marker
            strings such as ``@revoked``.
    """

    hosts: str
    key_type: str
    key: bytes
    marker: Optional[str] = None

    @property
    def hashed(self) -> bool:
        """True when the host field uses the ``|1|`` hashed form."""
        return self.hosts.startswith("|1|") or ",|1|" in self.hosts


class KnownHostsError(ValueError):
    """Raised when a non-blank, non-comment line cannot be parsed."""


def _unb64(token: str) -> bytes:
    """Decode a base64 token, tolerating missing padding.

    OpenSSH emits padded base64, but hand edited files and some tools drop the
    padding.  ``base64.b64decode`` with ``validate=False`` still rejects
    invalid characters, so we add padding ourselves and let it validate the
    alphabet.
    """
    padded = token + "=" * (-len(token) % 4)
    try:
        return base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise KnownHostsError(f"invalid base64 key material: {token!r}") from exc


def parse_known_host(record: str) -> Optional[KnownHost]:
    """Parse one line from a ``known_hosts`` file.

    Blank lines and comment lines (leading ``#``, optionally indented) return
    ``None``.  Every other line must have three or four whitespace separated
    fields; a trailing comment is permitted and ignored.

    Raises:
        KnownHostsError: if the line is structurally invalid or the key is not
            valid base64.
    """
    line = record.strip()
    if not line or line.startswith("#"):
        return None

    fields = line.split()
    marker: Optional[str] = None
    if fields[0] in MARKERS:
        marker = fields[0]
        fields = fields[1:]

    if len(fields) < 3:
        raise KnownHostsError(f"expected at least 3 fields, got {len(fields)}")

    hosts, key_type, key_b64 = fields[0], fields[1], fields[2]
    return KnownHost(
        hosts=hosts,
        key_type=key_type,
        key=_unb64(key_b64),
        marker=marker,
    )


def parse_known_hosts(text: str) -> Tuple[KnownHost, ...]:
    """Parse a whole file's worth of text into a tuple of records.

    Comments and blank lines are skipped.  A tuple is returned rather than a
    list so that callers cannot accidentally mutate shared state.
    """
    out = []
    for line in text.splitlines():
        parsed = parse_known_host(line)
        if parsed is not None:
            out.append(parsed)
    return tuple(out)
