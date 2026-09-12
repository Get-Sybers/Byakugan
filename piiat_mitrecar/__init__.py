"""Compat shim for the ``piiat_mitrecar`` -> ``byakugan`` import-package rename.

The repository, distribution, console script and import package are all named
**byakugan** now (issue #71). This package forwards every module and ``-m``
entry point to :mod:`byakugan` so existing imports and invocations keep working
for ONE release; it will then be removed — switch to ``import byakugan``.

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
