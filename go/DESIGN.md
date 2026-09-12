# Byakugan Go parse engine — design contract (v1)

Repo: /home/user/Byakugan (import package now `byakugan` after the rename; shim `piiat_mitrecar` exists).
Go module: `github.com/get-sybers/byakugan/go` (Go 1.24), lives at `go/` in the repo, mirroring DX_DFIR's layout.
Binary: `go/cmd/byakugan-parse` → built to `go/bin/byakugan-parse` by `go/Makefile` (`make -C go build`).

## Scope split (WHY)
The parsing-hot seam — raw processor files → pre-enrichment CAR event stream — moves to Go:
stream-reading (utf-8-sig BOM, errors='replace'), raw-l2t container splitting, winevt/jlecmd
adaptation, the 24-marker resolver over the declarative maps, uuid5/spindle guid minting.
Python KEEPS: mappings tables + normalize marker constructors (they are the introspection
substrate for sigma.py, sources_model, spindle drift guards, and the executable spec for the
300-test suite), enrich, store, superset, derive, stix, sigma, analytics, crosssource, timeline.
Python LOSES (deleted once parity is proven): pipeline's Python ingestion loop,
readers.iter_jsonl, adapters/l2t_split.py, adapters/winevt.py, adapters/jlecmd.py.
readers.load_piiat_car (sqlite passthrough) stays in Python.

## Single source of truth: the IR
`byakugan/export_ir.py` (new) serializes the live Python tables to `go/internal/ir/ir.json`:
- mappings: per artefact key {object, action, ts, guid, host, owning_pid, owning_guid, parent_pid,
  props: [[col, marker]...] (ordered pairs), keep: [...], native_extract: [[name, marker]...],
  variants: [[predicate_name, submap]...], default: submap|null}. Markers serialize as nested
  ["kind", arg...] arrays; field-name strings stay strings; guid specs as {"field":..}|{"fields":[..]}|
  {"marker":[..]}|{"spindle":name}|null.
- routes: ordered [substring_pattern, [keys]] pairs + evtx_maps list (content-routed set).
- spindle: full registry parsed from spindle.yml re-serialized as JSON (entries: identity field
  paths, version ints, scope, external forms, positional fallback [SourceImage, RecordId] v1).
- canon_user: the _canon_user well-known tables from normalize.py.
- predicate_names: sorted list (Go completeness check: every name must be registered in Go).
CLI: `python -m byakugan.export_ir [--out go/internal/ir/ir.json] [--check]`. `--check` byte-compares
(CI gate, like gen_sources --check). ir.json is committed; Go embeds it via go:embed.
The exporter must serialize markers by structure (tuples), never by repr.
MARKER ENCODING must be unambiguous (JSON loses Python's tuple-vs-list distinction):
a marker tuple ("kind", args...) serializes as {"!": ["kind", <arg>...]} where each arg is
recursively encoded (nested marker → {"!": [...]}, str/int/bool → literal, list → array,
dict (e.g. map_value tables) → object). A source arg that is a plain string means "field name";
{"!": ...} means nested marker — exactly mirroring normalize's isinstance(tuple) checks.

## Go packages (go/internal/...)
- `ir`: load/validate embedded IR; typed structs; ordered pairs preserved.
- `pyjson`: THE value model + Python-faithful JSON codec.
  - Decode: preserve int-vs-float distinction (json.Number-style: int if token has no ./e/E),
    strings exact, dict order = document order (ordered map type), null/bool. Accept and emit
    NaN/Infinity/-Infinity tokens exactly as Python json does (it allows them by default).
  - Encode `PyDumps(v)`: byte-identical emulation of Python `json.dumps(v)` DEFAULTS
    (ensure_ascii=True, separators=(', ', ': ')) AND canonical mode
    `PyCanonical(v)` = json.dumps(sort_keys=True, separators=(',',':'), ensure_ascii=False):
    key sort by UTF-8 bytes (== code points), Python escape table (\", \\, \n, \r, \t, \b, \f,
    other C0 as \u00xx lowercase hex; ensure_ascii mode: non-ASCII → \uXXXX with surrogate
    pairs for astral), float rendering = Python repr (shortest round-trip: strconv 'g' -1 with
    Python exponent fixups: e.g. 1e+16, 1e-05 — write targeted tests), int rendering unbounded
    (big ints: keep raw digits from decode; never float64-round large ints).
  - `PyStr(v)`: Python str() rendering (True→"True", False→"False", None→"None", int digits,
    float repr, str identity) used for guid field joins and RENDER_STR.
- `pyre`: regex adapter. Compiles Python-dialect patterns; the negative-lookahead idioms used by
  the maps (^(?!X$)(REST)$, \A(?!(?:X)\Z)(REST)\Z, ^(?!PFX)(REST)$) are translated to
  {deny regex, accept regex} pairs; everything else compiles as RE2 with `(?i)` etc. respected.
  regex1 marker returns group(1) or nil; match semantics = re.search unless pattern anchors.
- `record`: input record type (ordered pyjson object) + payload access: EvtxECmd `Payload` is a
  JSON-encoded STRING containing {EventData:{Data:[{"@Name":k,"#text":v}...]}} or
  {UserData:{<single child>:{...}}}; values str.strip()ed at index time, blank→nil; parse once
  per record (cache fine, identity semantics not needed). Separate UNSTRIPPED view for
  predicate gating (evtx_payload_field semantics: str(d.get('#text') or '')).
  Wrapped-plaso access R(key) = Record[key]. Blank rule: nil, "", "-" are all blank.
- `readers`: line streaming: utf-8-sig (strip one BOM), invalid UTF-8 → U+FFFD per Python
  'replace' semantics (validate against Python on crafted bytes), strip line whitespace,
  rstrip one trailing comma, skip blank/"["/"]" lines, skip json-invalid lines silently.
- `markers`: the 24-kind resolver mirroring normalize._resolve: first, const, basename (ntpath
  if '\\' in s else posixpath; trailing sep → ""→nil), ext (ntpath.splitext semantics), lower,
  regex1, domain_of, epoch_ts (numeric epoch → datetime.fromtimestamp(v, utc).isoformat():
  '+00:00' suffix, microseconds omitted when 0 else 6 digits, round-half-even to µs;
  already-ISO strings (s[:4].isdigit() gate) pass through UNCHANGED), map_value (optional
  upper=True pre-uppercase; miss → nil), concat (nil if ANY part blank), exe_path (quoted arg
  else cut at first case-insensitive '.exe' else first space token), payload, userdata,
  host_label, hex_int, unescape_backslashes, replace, at, ts_before (parse_ts: ' ' or 'T' sep,
  fraction ljust(6,'0') TRUNCATE at 6, Z/offset/naive=UTC), win_program_path, win_program_name,
  user_canon (tables from IR). _clean_ts drops ^(1601-01-01|1970-01-01|0001-01-01|1600-12-).
  Port each from the Python source EXACTLY (read normalize.py while implementing).
- `predicates`: hand-ported gate functions registered by name in per-family files
  (predicates_sysmon.go, predicates_evtx_windows.go, ... one file per Python mapping module).
  Registration: func init() { Register("name", fn) } — no shared file edits across families.
  SPECIAL: zeek_conn_has_state MUTATES the record (stamps _zc_end_time = ts+duration as ISO-Z
  microsecond-rounded string, _zc_packet_count = int(orig_pkts+resp_pkts) only when a counter
  exists, type-gated: string values don't count) — reproduce, incl. evaluation order
  (predicate runs before resolve).
- `spindle`: identity resolution over the NORMALIZED event (field paths, version, scope),
  positional fallback when any intrinsic component blank; emits native spindle_key/scope/ref.
- `ids`: SPINDLE_NS = uuid5(uuid5(NAMESPACE_URL, "https://github.com/Get-Sybers/PIIAT-MitreCar/stix"),
  "spindle"); mint = uuid5(SPINDLE_NS, PyCanonical({"_obj":obj,"_v":version, name:PyStr(value)...}));
  fields-guid = "<obj>-" + "-".join(PyStr(v)) with any-nil voiding. MUST pass every vector in
  model/spindle/golden.yml (Go test loads that YAML — small hand parser or yaml dep; prefer
  committed JSON copy exported in IR to avoid a YAML dep).
- `adapt`: winevt RULES table (positional strings → EvtxECmd shape E/U), jlecmd flatten
  (/Date(ms)/ → ISO), ported from the Python adapters.
- `split`: l2t container splitter: RecordId = 1-based PHYSICAL line number (blank/bad counted,
  skipped), table name 'L2t'+CamelCase(parser top segment), Timestamp = plaso µs epoch →
  fromtimestamp(µs/1e6).strftime('%Y-%m-%dT%H:%M:%S.%fZ') only when ts>0 (%f = always 6
  digits), output rows serialized with PyDumps default style byte-identical to Python's writer
  (check l2t_split.py for the exact json.dump call it uses), files written under --out-dir.
- `normalize`: orchestrates: select map entry → variants first-match via predicates → resolve
  action (nil → drop row) → build event in EXACT key order: car_object, car_action, timestamp
  (cleaned), guid, owning_pid, owning_guid_native, parent_pid, owning_guid=nil, parent_guid=nil,
  link_confidence=nil, source_artefact, source_host, _native {keep fields in list order +
  native_extract results (nil skipped) in declaration order + spindle_key/scope/ref}, then
  props merged in declaration order. guid minted LAST (spindle reads the normalized event).
  source_host: map-derived else --host fallback (fill AFTER normalize, as pipeline does).

## CLI contract
`byakugan-parse parse --in FILE --artefacts k1,k2 [--host H] [--adapter none|winevt|jlecmd]`
→ stdout: one event per line, encoded with PyDumps default-style (byte-identical to Python
json.dumps(event)); order = input order. Exit 0 even with 0 events; nonzero + stderr on I/O error.
`byakugan-parse split-l2t --in RAW.jsonl --out-dir DIR` → writes .L2t<Table> files, prints
JSON {"tables": {"L2tX": "path"...}, "lines": N} on stdout.
`byakugan-parse ir-check` → validates embedded IR against --in ir.json (optional utility).

## Parity harness (tests/parity/ in the repo)
- LAYOUT IS PER-FAMILY — no shared generator, no shared vector file. Every mapping family owns a
  disjoint set of paths so N agents can port N families in parallel without ever editing the same
  file (see "Per-family porting recipe" below for the exact contract).
- fixtures: tests/parity/fixtures/<artefact_or_family>/*.jsonl — REAL raw-shaped records:
  every inline fixture record extracted from the existing test files + authored fixtures for
  the zero-coverage maps (evtx_more variants per its docstring, plaso_fseventsd via
  to-be-validated/plaso_fseventsd_flags.yml research, plaso_olecf, full-field plaso_registry/
  shellitem/srum, readers edge cases: BOM, trailing commas, bad lines, bad UTF-8).
- each fixture dir carries manifest.json: {"artefacts": [keys], "host": "H"|null,
  "adapter": "none"|"winevt"|"jlecmd", "input": "<file>.jsonl"} — the runner discovers dirs.
- runner: tests/parity/test_go_parity.py — for each manifest: Python side runs the exact
  pre-enrichment reference path (readers/adapters/normalize — via tests/parity/reference/
  frozen copies of the plumbing that will be deleted (iter_jsonl, l2t_split, winevt, jlecmd),
  with the LIVE byakugan.normalize/mappings as the mapping spec) → json.dumps(ev) per event;
  Go side: byakugan-parse parse with the same manifest; assert BYTE-equal line by line.
  Builds the binary once per session via `go build` (pytest skip with clear reason if no Go
  toolchain; CI always has one). Split parity: reference l2t_split vs `split-l2t` on a
  synthetic container; byte-compare every output file.
- tests/parity/reference/ is created UP FRONT (before any deletion) as verbatim copies of
  readers.iter_jsonl + the three adapters with a frozen-reference header comment.
- golden vectors: Go unit test over model/spindle/golden.yml equivalents from IR (all 26
  identities + positional + 10 external forms + recipe vector).
- generators: `tests/parity/genf/<family>.py` — ONE script per mapping family, data-only, over
  the shared helpers in `tests/parity/genf/_lib.py` (`write_predicate_vectors`,
  `write_marker_vectors`, `write_fixture`, `j`). `tests/parity/gen_all.py` runs them all (or
  the families named on its argv), each in its own interpreter. The ENGINE-WIDE vector scripts
  (`gen_pyjson_vectors.py`, `gen_pyre_vectors.py`, `gen_reader_vectors.py`,
  `gen_spindle_vectors.py`) are shared files, unchanged, and are NOT run by gen_all.
- vectors: `go/internal/predicates/testdata/predicate_vectors/<family>.json` and
  `go/internal/markers/testdata/marker_vectors/<family>.json`. The Go tests GLOB those
  directories (sorted) and replay every file found, so adding a family is adding a file —
  never editing one. `marker_vectors/core.json` carries the engine-wide marker coverage (all 24
  kinds, `_clean_ts`, `parse_ts`, `evtx_payload_field`); a family adds its own marker file only
  when it needs coverage core does not already give it. A marker family file may carry any
  subset of the four sections (`resolve`, `clean_ts`, `parse_ts`, `payload_field`).

## Per-family porting recipe (N agents in parallel)
One agent = one mapping family = one disjoint file set. THE WHOLE POINT is that no two agents
ever open the same file, so the ONLY files a family agent may create or edit are:

    go/internal/predicates/predicates_<family>.go                    # func init(){Register(...)}
    go/internal/predicates/testdata/predicate_vectors/<family>.json  # generated, committed
    go/internal/markers/testdata/marker_vectors/<family>.json        # generated, ONLY if needed
    tests/parity/fixtures/<family>/ , tests/parity/fixtures/<family>_*/   # generated, committed
    tests/parity/genf/<family>.py                                    # the generator, data only

NEVER: any shared Go file (`predicates.go`, `normalize.go`, `markers.go`, `ir.go`, another
family's `predicates_*.go`), any shared test (`predicates_test.go`, `markers_test.go`,
`test_go_parity.py`, `harness.py`, `conftest.py`), `tests/parity/genf/_lib.py`,
`tests/parity/gen_all.py`, `go/internal/ir/ir.json`, `go/DESIGN.md`, `go/README.md`, ANY Python
engine code under `byakugan/` (the mapping tables and normalize are the SPEC — a port that needs
them changed is a wrong port, report it instead), and NEVER any git command (no add, commit,
branch, checkout, stash, rebase): the orchestrator commits.

Steps, start to finish:
1. Read the Python family module `byakugan/mappings/<family>.py` and, for every marker kind it
   uses, the matching branch of `byakugan/normalize.py`. The Python source wins over this doc.
2. Write `go/internal/predicates/predicates_<family>.go`: one `func <name>(r *record.Record) bool`
   per gate in that module's `PREDICATES`, plus a single
   `func init() { Register("name", name); ... }`. Package-private helper names must be prefixed
   with the family (`<family>_...` / `<family>Helper`) — the package is shared, the file is not.
3. Write `tests/parity/genf/<family>.py` as DATA over `_lib`: `PREDICATE_CASES` = (gate name,
   record) pairs covering every branch and every type edge (absent field, `None`, `""`, `"-"`,
   `str` vs `int` vs `float`, `bool`, mutation post-state); fixture rows = raw bytes per line.
   Copy the shape of `genf/core.py` (predicates + markers + two fixtures) or `genf/zeek_conn.py`
   (predicates + one fixture, mutating gate). Its `main()` may call ONLY
   `_lib.write_predicate_vectors(FAMILY, ...)`, `_lib.write_marker_vectors(FAMILY, ...)` and
   `_lib.write_fixture(<family or family_*>, ...)`.
4. Generate: `python tests/parity/genf/<family>.py` — writes only the family's own paths.
5. Prove it: `make -C go build test` (the globbing vector tests pick the new file up
   automatically) and `python -m pytest -q tests/parity` (the new fixture dir is discovered by
   `test_go_parity.py` automatically). Both must be green before reporting done.
6. Report: the family, the files created, any deviation found between the Python source and this
   doc (the Python source wins — the deviation is a note, never a code change to Python).

## Wiring + deletion (only after parity green)
pipeline.py: file ingestion goes through the Go binary (resolve: $BYAKUGAN_PARSE_BIN, PATH,
<repo>/go/bin/byakugan-parse; missing → actionable error naming `make -C go build`). Raw-l2t
sources: split via `split-l2t` into the same tempdir-under-out location. Passthrough car.db
stays Python. Delete: the Python read/normalize loop in pipeline.py, readers.iter_jsonl,
adapters/{l2t_split,winevt,jlecmd}.py (reference copies move to tests/parity/reference/).
Repoint the tests that exercised deleted units (adapter unit tests, shape-lock, routing tests
stay — route() remains Python) at the parity harness / Go binary. Everything else untouched.
CI (lint.yml): add go toolchain setup, `python -m byakugan.export_ir --check`, `make -C go build test`,
parity tests run inside pytest as before.

## Benchmark (report numbers honestly)
scripts/bench-parse.py: synthesize 500k-line EvtxECmd JSONL, 1M-line raw l2t container,
250k-line zeek conn.json; time Python reference (pre-deletion normalize loop) vs Go binary,
wall clock + peak RSS; print a small table. Run once and record results in go/README.md.

## Non-negotiables
- Frozen wire constants stay byte-identical (CAR_NS_URL string lives in Go ids too — copy verbatim).
- No new Python deps. Go deps: stdlib only if possible (no YAML — IR is JSON; uuid5 is sha1 —
  hand-roll, no external uuid dep needed).
- Event order = input order everywhere; no parallelism that reorders output (v1: sequential;
  concurrency inside a file only if order-preserving and proven equal).
- routes-to-[] and to-be-validated/ quarantined maps: Go must NOT emit them.
- Every deviation discovered between this doc and the Python source: THE PYTHON SOURCE WINS;
  note the deviation in your report.

## Stage A adjustments (recorded deviations — the Python source won)

1. **`l2t_winevt` / `jlecmd_dest` are adapter route keys, not plain mappings**
   (`pipeline._consume`): `l2t_winevt` reshapes each Plaso winevt/winevtx
   record through the winevt adapter and fans it through the WHOLE evtx map
   family; `jlecmd_dest` flattens each JLECmd record before its own map runs.
   The IR carries this as a top-level `adapters` section
   (`{key: {adapter, maps}}`); the routes stay verbatim.
2. **Marker encoding is per-kind positional**: `{"!": ["kind", <arg>...]}`
   spreads each kind's own constructor signature —
   variadic (`first`, `concat`) spread their sources; unary kinds carry one
   source; `regex1` = [src, pattern], `payload`/`userdata` = [field, key]
   (the STORED tuple order, field first), `map_value` = [src, table(sorted
   object), upper(bool)], `replace` = [src, old, new], `at` = [src, index],
   `ts_before` = [src, other], `const` = [literal]. A string arg in a source
   position is a field name; `{"!": ...}` is a nested marker — mirroring
   normalize._resolve's isinstance checks exactly.
3. **IR top-level schema (as built)**: `ir_version` (1), `marker_kinds`,
   `mappings` (sorted keys; an entry is `{variants: [[pred, leaf|null]...],
   default: leaf|null}` — or the leaf itself for a variant-less entry),
   `routes` (ordered pairs), `evtx_maps`, `adapters`, `spindle`
   ({namespace incl. the frozen CAR_NS_URL, object_key, version_key,
   renderings, positional, identities (identity as ordered
   [name, source, normalize|null] triples), external forms}), `canon_user`
   (the three well-known tables), `predicate_names` (sorted), `golden`
   (model/spindle/golden.yml re-encoded as JSON — the Go unit tests' vector
   table, no YAML dep). A leaf is `{object, action, ts, guid, host,
   owning_pid, owning_guid, parent_pid, props: [[col, spec]...], keep,
   native_extract: [[name, spec]...]}` with null for absent.
4. **pyre `$` semantics**: Python's `$` (end or before ONE final newline) is
   translated by rewriting a pattern-final `$` to `(?:\n)?\z` (nothing
   captures past it, so consuming the newline is group-equivalent) and `\Z`
   to Go's `\z`; the deny half of a translated lookahead applies the same
   rule to the lookahead body's own trailing anchor. Any other lookaround is
   a compile-time error, never a silent mis-match. Go's `\d`/`\w` are
   ASCII-only where Python 3's are Unicode-aware — no live pattern relies on
   the difference (the recorded vectors would catch one).
5. **pyjson lone surrogates** are stored as WTF-8 so an escaped surrogate
   pair and a lone surrogate both re-encode byte-identically; the parity
   vectors are lone-surrogate-free by design.

## Stage B adjustments (recorded deviations — the Python source won)

6. **The live runtime is Python 3.11, not 3.10** (the doc's parse_ts note
   named 3.10): zeek_conn's `_parse_ts` fromisoformat path therefore has
   3.11's LENIENT grammar, and the Go port matches the runtime — any-width
   fraction ('.'/',', first 6 digits used, the rest dropped), compact
   `YYYYMMDD`/`HHMMSS` forms, ANY single separator character, date-only,
   `Z` and `±HH[[:]MM[[:]SS]]` offsets. Not ported (→ unparseable, exactly
   like a junk string — never a mis-parse): ISO week/ordinal dates and
   fractional-second offsets. The predicate vectors pin the shapes the zeek
   lane can actually carry.
7. **epoch_ts on astronomically large epochs**: `datetime.fromtimestamp`
   raises OSError (NOT in normalize's except list) for |epoch| ≳ 1e18 — the
   Python engine CRASHES there. The Go engine treats it like the caught
   ValueError range (year outside 1..9999) and falls back to the
   ISO-passthrough gate. Both engines agree everywhere Python survives.
8. **iter_jsonl strips ALL trailing commas** (`rstrip(",")`), not one — the
   doc said "one trailing comma"; and non-object JSON lines are yielded by
   iter_jsonl in both engines (the reader vectors pin it), but a non-object
   RECORD crashes Python's normalize (AttributeError) where
   `byakugan-parse parse` exits 1 with a named error.
9. **str()/case-mapping corners**: Python `str()` of a CONTAINER (never
   produced by the live maps) is emulated with a Python-repr approximation;
   `.lower()`/`.upper()`/`isdigit()` are Unicode-simple/ASCII in Go where
   CPython applies full special casing (e.g. 'İ') and Unicode digits. No
   live field exercises the difference; the marker vectors include a
   container-repr case to pin the common shape.
10. **Predicate completeness is a HARD gate (stage C, done)**: all 77 IR
    predicate names are registered, so `predicates.Check` now fails the
    build rather than informing it — `byakugan-parse ir-check` exits 1 and
    names the gap, `TestRegistryAgainstIR` fails on a name in either
    direction (IR-but-not-Go, Go-but-not-IR, count mismatch), and
    `TestEveryRegisteredPredicateHasAVector` fails on a port with no
    recorded Python verdict. An actually-referenced unregistered predicate
    still fails `parse` loudly at evaluation, as before.
11. **Payload parse cache** lives on the Go Record struct (not as a
    `__car_parsed_payload__` key inside the record dict); observable
    behavior is identical because the engine never serializes the raw
    record and keep-lists never name the cache key. `Record.Set`
    invalidates the field's parse, mirroring the Python `is raw` check.
