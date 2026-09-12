"""Compat shim: ``piiat_mitrecar.gen_sources`` -> ``byakugan.gen_sources`` (one release only)."""
from byakugan.gen_sources import *  # noqa: F401,F403
from byakugan.gen_sources import main  # noqa: F401

if __name__ == "__main__":
    raise SystemExit(main())
