"""Compat shim for the ``piiat_mitrecar`` -> ``byakugan`` import-package rename.

The repository, distribution, console script and import package are all named
**byakugan** now (issue #71). For ONE release this shim preserves the old
surface so existing users aren't broken:

* ``import piiat_mitrecar`` / ``from piiat_mitrecar import ...`` re-export
  everything from :mod:`byakugan` (via the ``from byakugan import *`` below);
* ``python -m piiat_mitrecar`` forwards to the byakugan pipeline CLI (see
  ``piiat_mitrecar/__main__.py``);
* the ``piiat-mitrecar`` console script survives as an alias for ``byakugan``
  (declared in pyproject ``[project.scripts]``).

One thing does NOT carry over: the old ``piiat_mitrecar.adapters`` submodule is
gone — its EvtxECmd/jlecmd/log2timeline-split plumbing now lives in the Go parse
engine (``go/internal/{adapt,split}``) — so ``import piiat_mitrecar.adapters``
fails. Switch to ``import byakugan``; the shim is removed after this release.

Wire-format constants (``CAR_NS_URL``, the STIX producer identity seed) live
inside ``byakugan/ids.py`` and ``byakugan/stix.py`` and never depended on the
import name, so every previously minted deterministic id is unchanged.
"""
import warnings as _warnings

_warnings.warn(
    "the 'piiat_mitrecar' package was renamed to 'byakugan'; this compat shim "
    "will be removed after one release — import 'byakugan' instead",
    DeprecationWarning, stacklevel=2)

from byakugan import *  # noqa: F401,F403,E402
