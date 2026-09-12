"""Compat shim: ``piiat_mitrecar.derive`` -> ``byakugan.derive`` (one release only)."""
from byakugan.derive import *  # noqa: F401,F403
from byakugan.derive import main  # noqa: F401

if __name__ == "__main__":
    raise SystemExit(main())
