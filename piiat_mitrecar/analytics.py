"""Compat shim: ``piiat_mitrecar.analytics`` -> ``byakugan.analytics`` (one release only)."""
from byakugan.analytics import *  # noqa: F401,F403
from byakugan.analytics import main  # noqa: F401

if __name__ == "__main__":
    raise SystemExit(main())
