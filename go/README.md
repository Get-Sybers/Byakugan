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

## Layout (stages A + B)

| package            | what                                                              |
| ------------------ | ----------------------------------------------------------------- |
| `internal/pyjson`  | Python-faithful value model + JSON codec (`Dumps`, `Canonical`, `Str`) — byte-identical to CPython `json` / `str()`; vectors recorded by `tests/parity/gen_pyjson_vectors.py` |
| `internal/ids`     | the identity recipe of `byakugan/ids.py`: uuid5 chain, `Mint`, `GuidOf`, `Render`, `FieldsGuid` — pinned to `model/spindle/golden.yml` via the IR |
| `internal/pyre`    | Python-regex adapter: RE2 compile + the start-anchored negative-lookahead idiom as {deny, accept} pairs; vectors from `tests/parity/gen_pyre_vectors.py` |
| `internal/ir`      | embedded IR load + validation                                     |
| `internal/record`  | the input-record type: ordered object, blank rule, Python str()/truthiness/strip/int()/float(), EvtxECmd Payload lazy parse (stripped view) + `EvtxPayloadField` (unstripped gating view) |
| `internal/readers` | `iter_jsonl` semantics: utf-8-sig, errors='replace' maximal subparts, universal newlines, line cleaning; byte-level vectors from `tests/parity/gen_reader_vectors.py` |
| `internal/markers` | the 24-kind resolver (`normalize._resolve`), `parse_ts`, `_clean_ts`, epoch/isoformat rendering; vectors globbed from `testdata/marker_vectors/*.json`, written by `tests/parity/genf/<family>.py` (`core.json` = the engine-wide set) |
| `internal/predicates` | `Register(name, fn)` registry, per-family files (`predicates_core.go`, `predicates_zeek_conn.go` ported; stage C fills the rest), `Check` completeness gate; vectors globbed from `testdata/predicate_vectors/*.json`, one file per family, written by `tests/parity/genf/<family>.py` |
| `internal/spindle` | identity resolution over the normalized event + positional fallback + spindle natives; vectors from `tests/parity/gen_spindle_vectors.py` |
| `internal/normalize` | the orchestrator: variant select → action gate → exact event key order → natives → props → guid LAST |
| `cmd/byakugan-parse` | CLI: `parse` (adapter `none`) emits PyDumps event lines in input order; `ir-check` byte-compares + reports unported predicates; `split-l2t` + winevt/jlecmd adapters are stage C |

## Parity harness

`tests/parity/test_go_parity.py` runs every `tests/parity/fixtures/<name>/`
manifest through BOTH engines (frozen reference plumbing + live Python maps
vs `byakugan-parse parse`) and asserts per-line byte equality. Fixture dirs
are discovered by glob, so a newly ported family is picked up with no harness
edit. Exemplar families proven in stage B: `core_evtx_security`, `zeek_http`,
`zeek_conn`.

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
    python tests/parity/gen_all.py            # every genf/*.py
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

## Known, deliberate deltas from Python (stage A)

- `pyre`: Go's `\d`/`\w`/`\b` are ASCII-only where Python 3's are
  Unicode-aware. No mapping pattern relies on non-ASCII digits/words; the
  recorded vectors would catch a regression.
- `pyjson` stores a decoded lone surrogate as WTF-8 so it re-encodes
  identically; the parity vectors are lone-surrogate-free by design.
