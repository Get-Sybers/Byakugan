"""``python -m byakugan.exchange`` — run the STIX 2.1 / OpenCTI argparse CLI.

The dispatcher's exchange sub-tools (stix-export, stix-behaviour, cti-pull,
cti-sightings) route through the same CLI, keeping its exact behaviour and
its stdout=data / stderr=summary contract; nothing here alters it.
"""
from __future__ import annotations

from .cli import main

if __name__ == "__main__":
    main()
