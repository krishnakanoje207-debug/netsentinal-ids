"""Reading what an analyst typed into the search box.

One box, because the two things anybody searches an alert feed for are an address
and a technique, and asking which one it is before typing it is a question the
system can answer for itself. What was typed decides how it is matched:

* ``203.0.113.9`` - alerts from or to that address
* ``203.0.113.0/24`` - alerts from or to anything on that network
* ``T1046`` - alerts carrying that MITRE technique

The addresses are stored as ``INET``, not as text, so a network is matched by
containment in the database rather than by comparing strings. That is the difference
between a search that understands ``10.0.0.0/8`` and one that finds ``10.0.0.0/8``
only if somebody typed it into a hostname. It is also why a prefix search on text is
not offered: ``203.0.11`` matching ``203.0.113.9`` and ``203.0.110.0`` looks like a
feature until the one host you were chasing is missing from the results.

Anything else is refused with a sentence rather than matched loosely. A search box
that silently returns nothing teaches an analyst that there is nothing there.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

#: MITRE ATT&CK technique, with an optional sub-technique: T1046, T1071.001.
_TECHNIQUE = re.compile(r"^T\d{4}(\.\d{3})?$", re.IGNORECASE)


class Unsearchable(ValueError):
    """What was typed is neither an address, a network, nor a technique."""


@dataclass(frozen=True)
class AddressQuery:
    """Match alerts whose source or destination is inside this network.

    A bare address arrives here as a single-host network - ``/32`` or ``/128`` - so
    the query has one shape rather than two.
    """

    network: ipaddress.IPv4Network | ipaddress.IPv6Network

    def __str__(self) -> str:
        return str(self.network)


@dataclass(frozen=True)
class TechniqueQuery:
    """Match alerts carrying this MITRE technique."""

    technique: str

    def __str__(self) -> str:
        return self.technique


def parse(query: str) -> AddressQuery | TechniqueQuery:
    """Work out what was meant, or say what would have been understood."""
    text = query.strip()
    if not text:
        raise Unsearchable("search for an address, a network or a MITRE technique")

    if _TECHNIQUE.match(text):
        # Upper-cased on the way in: the column holds T1046, and an analyst who
        # types t1046 meant the same thing.
        return TechniqueQuery(text.upper())

    try:
        # strict=False so 203.0.113.9/24 is read as the network it names rather
        # than rejected for having host bits set. Somebody typing that means the
        # network, and a refusal there is pedantry.
        return AddressQuery(ipaddress.ip_network(text, strict=False))
    except ValueError:
        raise Unsearchable(
            f"cannot search for {text!r}; use an address (203.0.113.9), a network "
            "(203.0.113.0/24) or a technique (T1046)"
        ) from None
