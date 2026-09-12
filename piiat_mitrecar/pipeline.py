"""Compat shim: ``piiat_mitrecar.pipeline`` -> ``byakugan.pipeline`` (one release only)."""
from byakugan.pipeline import *  # noqa: F401,F403
from byakugan.pipeline import main  # noqa: F401

if __name__ == "__main__":
    raise SystemExit(main())
