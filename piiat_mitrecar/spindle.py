"""Compat shim: ``piiat_mitrecar.spindle`` -> ``byakugan.spindle`` (one release only)."""
from byakugan.spindle import *  # noqa: F401,F403
from byakugan.spindle import main  # noqa: F401

if __name__ == "__main__":
    raise SystemExit(main())
