"""Compat shim: ``piiat_mitrecar.timeline`` -> ``byakugan.timeline`` (one release only)."""
from byakugan.timeline import *  # noqa: F401,F403
from byakugan.timeline import main  # noqa: F401

if __name__ == "__main__":
    raise SystemExit(main())
