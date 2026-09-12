"""The frozen reference plumbing, for the unit tests whose subject moved to Go.

`byakugan/adapters/{winevt,jlecmd,l2t_split}.py` and `readers.iter_jsonl` are
gone: the Go parse engine (`go/bin/byakugan-parse`) does that work in the
pipeline now. Their verbatim Python copies live on under
`tests/parity/reference/` as the executable reference the byte-parity suite
holds the engine to — so a unit test whose ASSERTION is about that behaviour
(a positional winevt layout, a flattened jump-list entry, the wrapped l2t row
shape and its physical-line RecordId) keeps asserting exactly what it always
did, against the same code, now spelled as the spec rather than the engine.

Tests that assert the INGESTED result (real-evidence row counts) drive the
real engine instead — `pipeline.parse_events`.

    from reference_plumbing import winevt, jlecmd, l2t_split, iter_jsonl
"""
from __future__ import annotations

import os
import sys

_PARITY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "parity")
if _PARITY not in sys.path:
    sys.path.insert(0, _PARITY)

import harness  # noqa: E402  — tests/parity/harness.py owns the reference loader

winevt = harness._load_reference("winevt.py")                        # noqa: SLF001
jlecmd = harness._load_reference("jlecmd.py")                        # noqa: SLF001
l2t_split = harness._load_reference("l2t_split.py")                  # noqa: SLF001
iter_jsonl = harness._load_reference("readers_iter_jsonl.py").iter_jsonl  # noqa: SLF001
