# Copyright (C) 2012 Anaconda, Inc
# SPDX-License-Identifier: BSD-3-Clause
"""Optional py-rattler fast path for MatchSpec.

A thin facade: when ``py-rattler`` is installed we try to build a
``rattler.MatchSpec`` from the same spec string conda parsed, and when
the facade is asked to match a record we convert the ``PackageRecord``
to a ``rattler.PackageRecord`` the first time (cached on the conda
record itself) and use rattler's match implementation after that.

Everything here is optional and strictly additive: if rattler is not
importable, or it can't parse the spec grammar, or the record can't be
converted, the facade silently returns ``None`` and the caller falls
back to the existing conda-native match path.

Prototype only. Known gaps vs the pure-conda path:

- Edge-case spec syntaxes (``matchspec[key=value]`` extras, optional
  features) that conda supports but rattler doesn't; ``try_build()``
  returns ``None`` in that case so we fall through.
- ``PrefixRecord`` / ``PackageRecord`` subclasses with non-string
  version or unusual depends shapes; ``_to_rattler_record()`` catches
  exceptions and falls through.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

try:
    import rattler as _rattler  # noqa: F401
except ImportError:
    _rattler = None

if TYPE_CHECKING:
    from typing import Any

# Attribute name we stash the cached rattler view on, on conda records.
# Chosen to be unlikely to collide with any conda/auxlib field.
_CACHE_ATTR = "_conda_rattler_view"


def is_available() -> bool:
    """Return True if py-rattler is importable in this process."""
    return _rattler is not None


def try_build(spec_str: str) -> "Any | None":
    """Return a ``rattler.MatchSpec`` for ``spec_str``, or ``None`` if
    rattler is not installed or the spec grammar isn't supported."""
    if _rattler is None or not spec_str:
        return None
    try:
        return _rattler.MatchSpec(spec_str)
    except (ValueError, RuntimeError, TypeError):
        return None


def _to_rattler_record(rec) -> "Any | None":
    """Convert a conda ``PackageRecord`` / ``PrefixRecord`` to a
    ``rattler.PackageRecord``. Returns ``None`` on any conversion error
    so callers can fall back. Result is cached on ``rec`` itself so
    repeated matches against the same record pay the conversion cost
    only once."""
    if _rattler is None:
        return None
    cached = getattr(rec, _CACHE_ATTR, None)
    if cached is not None:
        return cached
    try:
        cached = _rattler.PackageRecord(
            name=rec.name,
            version=str(rec.version),
            build=rec.build or "",
            build_number=rec.build_number or 0,
            subdir=rec.subdir,
            noarch=_noarch_value(rec),
            depends=list(rec.depends or ()),
        )
    except (ValueError, RuntimeError, TypeError, AttributeError):
        return None
    try:
        setattr(rec, _CACHE_ATTR, cached)
    except (AttributeError, TypeError):
        # Record type forbids arbitrary attributes; that's fine, we just
        # don't cache and re-convert on the next call.
        pass
    return cached


def _noarch_value(rec) -> "str | None":
    """Extract a rattler-compatible noarch string from a conda record."""
    noarch = getattr(rec, "noarch", None)
    if noarch is None:
        # conda represents noarch-on-unknown-subdir via subdir == "noarch"
        # even when the record has noarch=None. Rattler expects an
        # explicit noarch type in that case.
        if getattr(rec, "subdir", None) == "noarch":
            return "generic"
        return None
    s = str(noarch).lower()
    if s in ("python", "generic"):
        return s
    if s == "true":
        return "generic"
    return None


def try_match(rattler_spec, rec) -> "bool | None":
    """Match ``rec`` against a pre-built rattler spec. Returns the
    boolean result, or ``None`` if anything fell through and the caller
    should use the conda-native match path."""
    if rattler_spec is None:
        return None
    rattler_rec = _to_rattler_record(rec)
    if rattler_rec is None:
        return None
    try:
        return bool(rattler_spec.matches(rattler_rec))
    except (ValueError, RuntimeError, TypeError):
        return None
