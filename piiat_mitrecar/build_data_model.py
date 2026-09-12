"""Compat shim: ``piiat_mitrecar.build_data_model`` -> ``byakugan.build_data_model`` (one release only)."""
from byakugan.build_data_model import *  # noqa: F401,F403
from byakugan.build_data_model import main  # noqa: F401

if __name__ == "__main__":
    raise SystemExit(main())
