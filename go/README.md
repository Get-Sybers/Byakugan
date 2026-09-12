# Byakugan Go parse engine

The parsing-hot seam of the Byakugan pipeline — raw processor files →
pre-enrichment CAR event stream — implemented in Go against the design
contract in [DESIGN.md](DESIGN.md). Python keeps the mapping tables and
everything after normalize; this engine EMBEDS a JSON snapshot of those
tables (`internal/ir/ir.json`, written by `python -m byakugan.export_ir`)
and must reproduce the Python engine's output byte for byte.

## Build

    make -C go build     # -> go/bin/byakugan-parse
    make -C go test      # go vet + go test ./...
    make -C go fmt

## Layout

| package            | what                                                              |
| ------------------ | ----------------------------------------------------------------- |
| `internal/pyjson`  | Python-faithful value model + JSON codec (`Dumps`, `Canonical`, `Str`) — byte-identical to CPython `json` / `str()`; vectors recorded by `tests/parity/gen_pyjson_vectors.py` |
| `internal/ids`     | the identity recipe of `byakugan/ids.py`: uuid5 chain, `Mint`, `GuidOf`, `Render`, `FieldsGuid` — pinned to `model/spindle/golden.yml` via the IR |
| `internal/pyre`    | Python-regex adapter: RE2 compile + the start-anchored negative-lookahead idiom as {deny, accept} pairs; vectors from `tests/parity/gen_pyre_vectors.py` |
| `internal/ir`      | embedded IR load + validation                                     |
| `internal/record`  | the input-record type: ordered object, blank rule, Python str()/truthiness/strip/int()/float(), EvtxECmd Payload lazy parse (stripped view) + `EvtxPayloadField` (unstripped gating view) |
| `internal/readers` | `iter_jsonl` semantics: utf-8-sig, errors='replace' maximal subparts, universal newlines, line cleaning; byte-level vectors from `tests/parity/gen_reader_vectors.py` |
| `internal/markers` | the 24-kind resolver (`normalize._resolve`), `parse_ts`, `_clean_ts`, epoch/isoformat rendering; vectors globbed from `testdata/marker_vectors/*.json`, written by `tests/parity/genf/<family>.py` (`core.json` = the engine-wide set) |
| `internal/predicates` | `Register(name, fn)` registry, one `predicates_<family>.go` per Python mapping module — all 77 IR predicates ported; `Check` is a HARD completeness gate (`ir-check` exits 1, `TestRegistryAgainstIR` fails). Vectors globbed from `testdata/predicate_vectors/*.json`, one file per family, written by `tests/parity/genf/<family>.py` |
| `internal/spindle` | identity resolution over the normalized event + positional fallback + spindle natives; vectors from `tests/parity/gen_spindle_vectors.py` |
| `internal/normalize` | the orchestrator: variant select → action gate → exact event key order → natives → props → guid LAST |
| `internal/adapt`   | the winevt RULES table (wrapped Plaso winevt/winevtx row → EvtxECmd shape) and the jlecmd DestList flatten, ported from `byakugan/adapters/` |
| `internal/split`   | the raw-l2t container splitter (`byakugan/adapters/l2t_split.py`): physical-line `RecordId`, `L2t<Camel>` table names, plaso-µs `Timestamp` |
| `cmd/byakugan-parse` | CLI: `parse` (adapters `none`/`winevt`/`jlecmd`, adapter-route-key fan-out) emits PyDumps event lines in input order; `split-l2t` writes the per-parser table files + a JSON summary; `ir-check` validates the embedded IR, byte-compares `--in`, and FAILS on any unported IR predicate |

## How the pipeline uses it

`python -m byakugan` parses EVERY file source through this binary — there is no
Python ingestion path left. `byakugan/pipeline.py` resolves it via
`$BYAKUGAN_PARSE_BIN`, then `<repo>/go/bin/byakugan-parse`, then `PATH`, and
exits with a `make -C go build` hint if it finds none; it then calls

    byakugan-parse parse --in FILE --artefacts k1,k2 [--host H] [--adapter winevt|jlecmd]

once per source file (the routed map keys of that file, adapter route keys
`l2t_winevt` / `jlecmd_dest` passed verbatim and fanned out here via
`ir.adapters`) and `json.loads`es the emitted lines straight into the
unchanged enrich → store → superset → derive → STIX path, and

    byakugan-parse split-l2t --in RAW.jsonl --out-dir TMP

for a raw log2timeline container, into a tempdir under the source's output dir.
Routing (`pipeline.ROUTES`), the mapping tables, normalize's marker
constructors (the introspection substrate for sigma/sources_model/spindle) and
the PIIAT-Mem `car.db` passthrough stay in Python.

## Parity harness

`tests/parity/test_go_parity.py` runs every `tests/parity/fixtures/<name>/`
manifest through BOTH engines (frozen reference plumbing + live Python maps
vs `byakugan-parse parse`) and asserts per-line byte equality. Fixture dirs
are discovered by glob, so a newly ported family is picked up with no harness
edit. All 38 IR artefact keys are covered by at least one fixture, across 42
fixture directories (adapter fan-out included). `tests/parity/test_split_parity.py`
does the same for `split-l2t` against the frozen reference splitter.

## Benchmark

Measured, never estimated. `scripts/bench-parse.py` synthesises a corpus whose
record shapes are cloned from `tests/parity/fixtures/*/input.jsonl`, proves both
sides emit **byte-identical output on a head slice of that very corpus** before
timing anything, then times the frozen pre-migration Python path
(`tests/parity/reference/` plumbing driving the live maps — the implementation
this engine replaced) against this binary. Best wall clock of three runs per
side, both writing to `/dev/null`, each side a fresh child process; CPU time
from the child's rusage, peak RSS from its `/proc/<pid>/status` VmHWM.

    python scripts/bench-parse.py --repeat 3        # ~3.5 min; the corpus is deleted after

| corpus | input | records | events | Python wall (cpu) | Go wall (cpu) | wall speed-up | peak RSS py / go |
| --- | --- | --- | --- | --- | --- | --- | --- |
| EvtxECmd Security -> evtx_security | 98 MiB | 200,000 | 120,000 | 7.81 s (7.81) | 6.52 s (9.62) | **1.20x** | 21.5 / 11.9 MiB |
| Zeek conn.json -> zeek_conn | 63 MiB | 150,000 | 130,000 | 6.09 s (6.08) | 5.26 s (7.93) | **1.16x** | 21.6 / 11.7 MiB |
| raw l2t container -> split-l2t | 155 MiB | 400,000 | 6 tables | 8.92 s (8.91) | 8.56 s (9.05) | **1.04x** | 18.2 / 10.0 MiB |
| l2t L2tFilestat table -> l2t_filestat | 48 MiB | 82,155 | 76,678 | 7.85 s (7.83) | 4.11 s (5.78) | **1.91x** | 22.3 / 12.1 MiB |

Host: Intel Xeon @ 2.80GHz, 4 vCPU · Linux 6.18.44 · CPython 3.11.15 · go1.24.7
— a shared cloud VM, so the absolute seconds are host-specific; the ratios are
what travels. The Python column carries interpreter start-up and import cost
(~0.25 s), exactly as the pipeline used to pay it per source.

Read honestly, that is a **modest win, not an order of magnitude**, and the
shape of it is worth knowing before optimising anything here:

- The margin tracks how much MAPPING work a record carries. The l2t table row
  (many marker resolutions, predicates and identity per record) is ~1.9x; the
  `split-l2t` row is JSON decode + re-encode and almost nothing else, so the two
  implementations are level (1.04x) — Go buys nothing where CPython's C-coded
  `json` already does the work.
- Go spends MORE CPU than Python on three of four corpora while finishing sooner
  in wall clock: the runtime's collector runs on other cores. On a machine with
  no spare core the wall-clock win would shrink toward the CPU ratio.
- Peak RSS is roughly halved on every corpus, and both sides stream — neither
  grows with input size.
- The ceiling is deliberate: this engine reproduces CPython's `json` and `str()`
  byte for byte (ordered objects, Python-identical float and escape rendering,
  a boxed value model — see `internal/pyjson`). Fidelity is the product; speed
  is the bonus. The honest reason to have moved the stage is that ingestion is
  now one self-contained, testable binary with a byte-pinned contract, with a
  ~1.0–1.9x wall-clock and ~2x memory improvement on top.

## Dependencies

`go.mod` is this engine's requirements file and it is **stdlib-only** — no
`require` block, no third-party modules, and therefore no `go.sum` (CI sets
`cache: false` for exactly that reason). The mapping tables it needs are not
fetched either: `internal/ir/ir.json` is embedded at build time. Upgrading the
Go side means bumping the `go` directive in `go.mod` (and the toolchain version
in `.github/workflows/lint.yml` + CONTRIBUTING.md), then re-running
`make -C go build test` and `pytest -q tests/parity`.
`tests/test_requirements_sync.py::test_go_module_is_stdlib_only` fails the
moment a third-party module or a `go.sum` appears, so this paragraph cannot go
stale. The Python side's inventories are `requirements.txt` and
`requirements-dev.txt` at the repo root.

## Regenerating the IR and vectors

    python -m byakugan.export_ir              # rewrites go/internal/ir/ir.json
    python -m byakugan.export_ir --check      # CI drift gate

Engine-wide vectors (shared files, one script each):

    python tests/parity/gen_pyjson_vectors.py
    python tests/parity/gen_pyre_vectors.py
    python tests/parity/gen_reader_vectors.py
    python tests/parity/gen_spindle_vectors.py

Per-family predicate vectors, marker vectors and fixtures — ONE script per
mapping family, each writing only its OWN files so families can be ported in
parallel without touching a shared path:

    python tests/parity/genf/core.py          # core.py: evtx_security + zeek_http
    python tests/parity/genf/zeek_conn.py     # zeek_conn.py
    python tests/parity/gen_all.py            # every genf/*.py (15 families)
    python tests/parity/gen_all.py core       # just these families

A family script writes exactly:

    go/internal/predicates/testdata/predicate_vectors/<family>.json
    go/internal/markers/testdata/marker_vectors/<family>.json   (only if needed)
    tests/parity/fixtures/<family>/ , tests/parity/fixtures/<family>_*/

The Go tests GLOB `testdata/predicate_vectors/*.json` and
`testdata/marker_vectors/*.json` and replay every file, and
`tests/parity/test_go_parity.py` discovers every fixture directory — so adding
a family means ADDING files, never editing shared ones. The full contract
(what a family agent may and may not touch) is the "Per-family porting recipe"
section of [DESIGN.md](DESIGN.md).

## Known, deliberate deltas from Python

The complete, numbered list is in [DESIGN.md](DESIGN.md) ("Stage A/B adjustments");
the two that bite most often:

- `pyre`: Go's `\d`/`\w`/`\b` are ASCII-only where Python 3's are
  Unicode-aware. No mapping pattern relies on non-ASCII digits/words; the
  recorded vectors would catch a regression.
- `pyjson` stores a decoded lone surrogate as WTF-8 so it re-encodes
  identically; the parity vectors are lone-surrogate-free by design.
