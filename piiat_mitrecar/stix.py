"""Compat shim: ``piiat_mitrecar.stix`` -> ``byakugan.stix`` (one release only)."""
from byakugan.stix import *  # noqa: F401,F403
from byakugan.stix import main  # noqa: F401

if __name__ == "__main__":
    raise SystemExit(main())
