"""prefetch_dump → CAR — the Get-Sybers Windows Prefetch data source.

`prefetch_dump` (the Get-Sybers/GoDFIR-toolz `get-sybers/goprefetch` container,
Go on Velociraptor's go-prefetch) parses Windows `.pf` natively on Linux —
Windows XP through Windows 11, including the Xpress-Huffman (MAM) compression
Windows 8+ prefetch uses. It emits one JSONL record
per `.pf`: `Executable`, `Path` (the run-from device path), `Hash`, `Version`,
`RunCount`, `LastRun` + `PreviousRuns[]` (up to eight run times a `.pf` retains),
and `FilesAccessed[]`.

**Prefetch is prefetch regardless of parser** (docs: artefact ≠ processor), so
this links to the SAME CAR object the Plaso prefetch map does —
**windows:prefetch:execution → process/create** (execution evidence: the program
demonstrably ran) — but as its OWN MITRE data source with its OWN positional row
identity (a `{"fields": …}` guid, the spindle external form every non-Plaso map
carries verbatim; the Plaso spindle registry is Plaso-only). Verified against
real `.pf`: `Executable`/`Hash` match Plaso
(`0x4E6085D4` == 1314948564), one execution per `.pf`.

- `exe` is the `Executable` name; `image_path` is the full run-from `Path` where
  the `.pf` records it, an honest null otherwise (the Anamnesis process
  convention — a bare name never fabricates a path).
- Timestamped at `LastRun` (the most recent run); the earlier `PreviousRuns` and
  the run count / accessed files / volume metadata stay native.

Row identity (positional, this-source-only): the executable + the `.pf` path hash
— the pair the `.pf` filename itself is keyed on (one execution artefact per file).
"""
from __future__ import annotations


def prefetch_dump_is_execution(rec) -> bool:
    """A parsed `.pf` execution record — it names an executable."""
    return bool(rec.get("Executable"))


PREDICATES = {"prefetch_dump_is_execution": prefetch_dump_is_execution}
