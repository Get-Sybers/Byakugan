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

## Layout (stage A)

| package            | what                                                              |
| ------------------ | ----------------------------------------------------------------- |
| `internal/pyjson`  | Python-faithful value model + JSON codec (`Dumps`, `Canonical`, `Str`) — byte-identical to CPython `json` / `str()`; vectors recorded by `tests/parity/gen_pyjson_vectors.py` |
| `internal/ids`     | the identity recipe of `byakugan/ids.py`: uuid5 chain, `Mint`, `GuidOf`, `Render`, `FieldsGuid` — pinned to `model/spindle/golden.yml` via the IR |
| `internal/pyre`    | Python-regex adapter: RE2 compile + the start-anchored negative-lookahead idiom as {deny, accept} pairs; vectors from `tests/parity/gen_pyre_vectors.py` |
| `internal/ir`      | embedded IR load + validation                                     |
| `cmd/byakugan-parse` | CLI skeleton (`parse` / `split-l2t` land in stage B; `ir-check` works) |

## Regenerating the IR and vectors

    python -m byakugan.export_ir              # rewrites go/internal/ir/ir.json
    python -m byakugan.export_ir --check      # CI drift gate
    python tests/parity/gen_pyjson_vectors.py
    python tests/parity/gen_pyre_vectors.py

## Known, deliberate deltas from Python (stage A)

- `pyre`: Go's `\d`/`\w`/`\b` are ASCII-only where Python 3's are
  Unicode-aware. No mapping pattern relies on non-ASCII digits/words; the
  recorded vectors would catch a regression.
- `pyjson` stores a decoded lone surrogate as WTF-8 so it re-encodes
  identically; the parity vectors are lone-surrogate-free by design.
