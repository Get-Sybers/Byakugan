"""Plaso execution evidence → MITRE CAR `process` maps (epic #86, Phase 2).

Port of the vetted KQL views `CarProcess_Plaso` and `CarProcess_Cron`
(kusto/schema/40-mitre.kql) onto the declarative engine. The raw shape is the
wrapped l2t JSONL the plaso lane emits (ingest/prepare.split_l2t):
``{"SourceImage", "Timestamp", "Parser", "Record": {<flat plaso event>}}`` —
`Record` fields are reached with the `payload` marker scoped to "Record".

Three artefact keys, matching the lane's per-parser table split:

- **plaso_exec_prefetch** ← L2tPrefetch. Only `windows:prefetch:execution`
  rows are runs; the parser's `windows:volume:creation` rows are volume
  metadata (no program) and stay raw.
- **plaso_exec_winreg** ← L2tWinreg (and an L2tAmcache / L2tBam table, should
  a plaso version emit those parsers outside winreg/): amcache, userassist,
  bam, appcompatcache. The KQL's `programscache` rows carry no program-path
  field at all — nothing provable maps, so they stay raw (canonical-or-raw).
- **plaso_exec_cron** ← L2tText: `syslog:cron:task_run`.

Field semantics follow MITRE's own docs (car.mitre.org) and the KQL view's
per-parser findings, with the engine's stricter null-over-near-miss rules
(docs/CAR-Relations.md; car-store.md §3):

- The EXECUTED PROGRAM's path lives in a different Record field per parser —
  NEVER in Record.filename/display_name, which name the parsed ARTEFACT file
  itself (the .pf file, the hive) and must not leak into exe/image_path.
  Likewise the top-level Record.sha256_hash is the ARTEFACT file's own hash —
  never a program hash (it is kept native as provenance only).
- `exe` is the executable NAME (MITRE: the process's executable) and
  `image_path` the FULL path — where only a bare name is provable (XP-era
  prefetch, a shell builtin in a cron command line) `exe` carries it and
  `image_path` stays an honest null, per the Anamnesis process convention.
  (The KQL put the same value in both; the engine's rule is stricter.)
- `action="create"` records the vetted judgement that each row EVIDENCES a
  program execution (prefetch run, shimcache/amcache presence with the
  execution inference the KQL ratified, userassist run counter, bam last-run,
  cron task_run). The artefact timestamps differ in meaning (last-run,
  file-mtime, log-line time) — `timestamp_desc` is kept native so the analyst
  sees which. Shimcache (appcompatcache) over-asserts twice — presence is not
  proof of a run, and its timestamp is the cached file's $SI mtime, not a run
  time — so those rows are KEPT (analysts expect them) but labelled:
  `native.execution_inferred = True` and `native.time_meaning` state exactly
  what the row proves.
- Amcache's "Link Time" row is the program's PE header TimeDateStamp — when
  the binary was COMPILED, never when it ran. It is not an execution, and not
  a host file event either: it maps to a timestamp-less **file** record that
  carries the compile stamp natively (`native.compile_time`), so the compile
  time survives without ever entering the timeline. (Plaso emits one row per
  date-time attribute of an entry and its JSON carries none of the others on
  a row, so the compile time can live only on this row.) The other amcache
  rows — the key write plaso labels 'Content Modification Time', file
  creation/modification, installation — keep the execution mapping.
- No native record identity exists (no EventRecordId analogue), so `guid` is
  the MINTED spindle id: uuid5 over the artefact's own stable fields, declared
  per entry in byakugan/spindle.yml (docs/CAR-Pipeline.md §7.1) — the
  prefetch (exe + prefetch_hash) at its run time, the userassist key + value
  name and the bam key + path at their run time, the cron line (command + pid)
  at its line time; the amcache and appcompatcache program path at the row's
  RECORDED stamp (an inferred-meaning time — `recorded_time`, never a run
  time); the amcache Link Time row as a time-free ENTITY record (path + the
  program's SHA-1). One entry carries several same-action rows (eight last-run
  times in a Win8+ .pf), so the time is part of an EVENT identity; rows that
  differ only in native stamps share an ENTITY identity. A leaf only names
  its entry.
"""
from __future__ import annotations

import re

from ..normalize import (basename, const, ext, first, lower, map_value,  # noqa: F401
                         payload, regex1, user_canon, win_program_name,
                         win_program_path)
from ._common import (R as _R, spindle as _spindle,
                      user_from_path as _user_from_path)


# --- variant predicates (globally-unique names, plaso_ prefixed) -------------

def plaso_is_prefetch_execution(rec) -> bool:
    """L2tPrefetch carries both windows:volume:creation (volume metadata, no
    program) and windows:prefetch:execution — only the latter is a run."""
    record = rec.get("Record") or {}
    return record.get("data_type") == "windows:prefetch:execution"


def _parser(rec) -> str:
    return str(rec.get("Parser") or "").lower()


def _timestamp_desc(rec) -> str:
    return str((rec.get("Record") or {}).get("timestamp_desc") or "")


# plaso's "Link Time" (definitions.TIME_DESCRIPTION_LINK_TIME) — the PE header
# TimeDateStamp; tolerant of a "Compilation Time" rendering
_COMPILE_STAMP = re.compile(r"(?i)link|compil")


def plaso_is_amcache_link_time(rec) -> bool:
    """The amcache row whose timestamp is the program's PE "Link Time": the
    header TimeDateStamp, i.e. when the binary was COMPILED — never a run."""
    return "amcache" in _parser(rec) and bool(_COMPILE_STAMP.search(_timestamp_desc(rec)))


def plaso_is_amcache(rec) -> bool:
    """An amcache row that EVIDENCES execution (the ratified inference): every
    dated row of an entry EXCEPT the Link Time one — the key write (plaso:
    'Content Modification Time'), file creation/modification, installation."""
    return "amcache" in _parser(rec) and not plaso_is_amcache_link_time(rec)


def plaso_is_userassist_run(rec) -> bool:
    """Only userassist rows that EVIDENCE a program run map. XP-format value
    names: `UEME_RUNPATH:<path>` is a program execution; UEME_RUNPIDL (a
    shortcut/PIDL — no program path recorded), UEME_RUNCPL (a .cpl applet —
    the backing executable is unrecorded), UEME_CTL*/UEME_UISCUT (session and
    UI counters — not executions) stay raw. Win7+ plaso decodes value names to
    the bare path (no UEME_ prefix) — those map too. The vetted KQL mapped
    every userassist row; the store's canonical-or-raw rule tightens that: a
    `process create` whose exe would be `UEME_CTLSESSION` asserts an execution
    the evidence doesn't contain."""
    if "userassist" not in _parser(rec):
        return False
    vn = str((rec.get("Record") or {}).get("value_name") or "")
    return vn.startswith("UEME_RUNPATH:") or (bool(vn) and not vn.startswith("UEME_"))


def plaso_is_bam(rec) -> bool:
    # token match — "bam" as a path segment ("winreg/bam"), not a substring
    return bool(re.search(r"(?:^|/)bam(?:/|$)", _parser(rec)))


def plaso_is_appcompatcache(rec) -> bool:
    return "appcompatcache" in _parser(rec)


def plaso_is_cron_task_run(rec) -> bool:
    record = rec.get("Record") or {}
    return record.get("data_type") == "syslog:cron:task_run"


PREDICATES = {
    "plaso_is_prefetch_execution": plaso_is_prefetch_execution,
    "plaso_is_amcache_link_time": plaso_is_amcache_link_time,
    "plaso_is_amcache": plaso_is_amcache,
    "plaso_is_userassist_run": plaso_is_userassist_run,
    "plaso_is_bam": plaso_is_bam,
    "plaso_is_appcompatcache": plaso_is_appcompatcache,
    "plaso_is_cron_task_run": plaso_is_cron_task_run,
}


# --- shared blocks ----------------------------------------------------------

# hostname: MITRE "The hostname of the machine [the process ran on]" — the
# image's identity, stamped by the lane (Record.image_hostname), verbatim as
# the KQL maps it. Doubles as the enrich scope key (host).
_IMG_HOST = _R("image_hostname")


# amcache stores the PROGRAM's SHA-1 in `file_identifier` — the plaso field is
# the hive's 4-char record-length prefix "0000" followed by the 40-hex SHA-1
# (e.g. "00009842cd16…afcbee"). The bare `sha1` key the KQL port reached for
# does not exist in the shipping plaso build, so amcache's hash reached NO
# object at all. Extract the 40-hex SHA-1 honestly (null unless it is exactly
# that "0000"+40hex shape — never the hive's own sha256_hash). Canonicalised to
# LOWERCASE so it equates with a hash emitted by any other source/map.

# provenance of the observation — the ARTEFACT file (never exe/image_path) and
# its own hash, plus which plaso event this was


def _win_props(image_path_marker):
    """The common process props for the Windows execution artefacts: full path
    into image_path, its basename into exe, plus user and host identity.

    exe/image_path go through win_program_name/win_program_path so a modern
    Store/UWP AppCompatCache (or Amcache) entry — a TAB-delimited package
    descriptor, not a filesystem path — yields the clean Package Family Name in
    exe and a null image_path, NEVER the raw tab blob (a real path is unchanged).
    """
    return {
        "exe": win_program_name(image_path_marker),
        "image_path": win_program_path(image_path_marker),
        # plaso's username is "-" on most registry/prefetch rows — the payload
        # marker's blank rules turn that into an honest null; user_canon folds a
        # well-known account (SYSTEM/LOCAL|NETWORK SERVICE) to its canonical token
        "user": user_canon(_R("username")),
        "hostname": _IMG_HOST,
    }
