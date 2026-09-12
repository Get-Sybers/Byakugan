"""Compat shim: ``piiat_mitrecar.crosssource`` -> ``byakugan.crosssource`` (one release only)."""
from byakugan.crosssource import *  # noqa: F401,F403
from byakugan.crosssource import main  # noqa: F401

if __name__ == "__main__":
    raise SystemExit(main())
