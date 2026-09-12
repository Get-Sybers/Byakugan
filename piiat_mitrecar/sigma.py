"""Compat shim: ``piiat_mitrecar.sigma`` -> ``byakugan.sigma`` (one release only)."""
from byakugan.sigma import *  # noqa: F401,F403
from byakugan.sigma import main  # noqa: F401

if __name__ == "__main__":
    raise SystemExit(main())
