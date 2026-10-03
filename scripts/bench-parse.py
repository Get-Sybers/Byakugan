#!/usr/bin/env python3
"""Measure the Go parse engine against the Python path it replaced.

The migration's claim is "same bytes, less time" — the byte half is proven by
`tests/parity` (per-line byte equality on 42 fixtures); THIS script measures the
other half, on a corpus big enough for the numbers to mean something.

    python scripts/bench-parse.py --workdir /tmp/bench          # full corpus
    python scripts/bench-parse.py --scale 0.1 --repeat 1        # a quick look

What is compared
----------------
*   **Python reference** — the FROZEN pre-migration plumbing under
    `tests/parity/reference/` (the deleted `readers.iter_jsonl`) driving the LIVE
    `byakugan.normalize` + mapping tables: exactly what
    `tests/parity/harness.run_python_reference` runs, except that the events are
    STREAMED to stdout instead of accumulated in a list — otherwise the RSS
    column would measure a Python list of every event against a Go program that
    streams, which is not a comparison of the parse work.
*   **Go engine** — `go/bin/byakugan-parse parse` / `split-l2t`, the binary the
    pipeline actually shells out to, over the same files with the same argv the
    pipeline would use.

Both sides write to /dev/null, both are run as a fresh child process, and each
side is timed `--repeat` times with the best wall clock reported. Wall clock and
CPU time come from `os.wait4` (the child's own rusage) and peak RSS from the
child's `/proc/<pid>/status` VmHWM, so the Python column honestly carries its
interpreter start-up and import cost — the pipeline pays it on every source
too. Before every timed pair the script parses a HEAD SLICE of the same corpus
through both sides and compares sha256: a benchmark of two programs that disagree
would be meaningless, so the comparison is proven like-for-like each run.

The corpus is synthesised (not committed): records are cloned from the shapes in
`tests/parity/fixtures/*/input.jsonl` — real EvtxECmd/Zeek/Plaso field sets — with
the identity-bearing fields (record ids, timestamps, hosts, users, ips, ports,
paths) varied per row so nothing degenerates into one repeated record. It is
written under `--workdir`, deleted phase by phase as the script goes, and the
whole directory is removed at the end unless `--keep` is passed.

Nothing here is a fixture or a test: the script writes no repo file. Paste the
printed markdown table into go/README.md's Benchmark section when re-measuring,
with the host line it prints.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import platform
import random
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
PARITY = os.path.join(REPO, "tests", "parity")
FIXTURES = os.path.join(PARITY, "fixtures")
GO_BIN = os.path.join(REPO, "go", "bin", "byakugan-parse")
DEVNULL = "/dev/null"

# full-corpus line counts (scaled by --scale)
EVTX_LINES = 200_000
L2T_LINES = 400_000
ZEEK_LINES = 150_000

HEAD_SLICE = 4_000          # lines byte-compared before each timed pair


# --------------------------------------------------------------------------- #
# the two sides, as child processes
# --------------------------------------------------------------------------- #
def _reference_modules():
    """The frozen reference plumbing, loaded through the parity harness's own
    loader — the same modules the parity suite compares the engine against."""
    if PARITY not in sys.path:
        sys.path.insert(0, PARITY)
    if REPO not in sys.path:
        sys.path.insert(0, REPO)
    import harness                                     # noqa: PLC0415
    return harness


def worker_parse(path: str, artefacts: list[str], host: str | None) -> int:
    """harness.run_python_reference's inner loop, streamed to stdout."""
    harness = _reference_modules()
    from byakugan import normalize                     # noqa: PLC0415
    iter_jsonl = harness._load_reference("readers_iter_jsonl.py").iter_jsonl  # noqa: SLF001

    out = sys.stdout
    dumps = json.dumps
    n = 0
    for rec in iter_jsonl(path):
        for art in artefacts:
            ev = normalize.normalize(art, rec)
            if ev is None:
                continue
            if not ev.get("source_host"):     # pipeline fills AFTER normalize
                ev["source_host"] = host
            out.write(dumps(ev))
            out.write("\n")
            n += 1
    out.flush()
    print(f"EVENTS {n}", file=sys.stderr)
    return 0


def worker_split(path: str, out_dir: str) -> int:
    """The frozen l2t container splitter, called as pipeline._process called it."""
    harness = _reference_modules()
    l2t_split = harness._load_reference("l2t_split.py")                      # noqa: SLF001
    os.makedirs(out_dir, exist_ok=True)
    base = os.path.basename(path)
    tables = l2t_split.split_l2t(path, base, out_dir, base)
    print(f"TABLES {len(tables)}", file=sys.stderr)
    return 0


def ref_parse_argv(path: str, artefacts: list[str], host: str | None) -> list[str]:
    argv = [sys.executable, os.path.abspath(__file__), "--worker", "parse",
            "--in", path, "--artefacts", ",".join(artefacts)]
    if host:
        argv += ["--host", host]
    return argv


def ref_split_argv(path: str, out_dir: str) -> list[str]:
    return [sys.executable, os.path.abspath(__file__), "--worker", "split",
            "--in", path, "--out-dir", out_dir]


def go_parse_argv(path: str, artefacts: list[str], host: str | None) -> list[str]:
    argv = [GO_BIN, "parse", "--in", path, "--artefacts", ",".join(artefacts)]
    if host:
        argv += ["--host", host]
    return argv


def go_split_argv(path: str, out_dir: str) -> list[str]:
    return [GO_BIN, "split-l2t", "--in", path, "--out-dir", out_dir]


# --------------------------------------------------------------------------- #
# measurement
# --------------------------------------------------------------------------- #
class Run:
    def __init__(self, wall: float, cpu: float, rss_kb: int, stderr: str):
        self.wall, self.cpu, self.rss_kb, self.stderr = wall, cpu, rss_kb, stderr


def _vm_hwm_kb(pid: int) -> int:
    """/proc/<pid>/status VmHWM — the kernel's high-water mark for THIS mm.

    Deliberately not rusage's ru_maxrss: a spawned child inherits its parent's
    accounted peak across fork+exec, so ru_maxrss reports a floor of whatever
    this benchmark process itself is holding (~24 MiB), which silently made
    both engines look identical. VmHWM belongs to the post-exec mm and is
    monotonic, so polling it and keeping the last reading gives the child's own
    peak (a run shorter than the poll interval is the only blind spot)."""
    try:
        with open(f"/proc/{pid}/status", encoding="ascii") as fh:
            for line in fh:
                if line.startswith("VmHWM:"):
                    return int(line.split()[1])
    except (OSError, ValueError, IndexError):
        pass
    return 0


def measure(argv: list[str], stdout_path: str, err_path: str) -> Run:
    """Run argv to completion; wall clock + CPU (rusage) + peak RSS (VmHWM)."""
    fa = [(os.POSIX_SPAWN_OPEN, 1, stdout_path,
           os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644),
          (os.POSIX_SPAWN_OPEN, 2, err_path,
           os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)]
    t0 = time.perf_counter()
    pid = os.posix_spawn(argv[0], argv, os.environ, file_actions=fa)
    hwm = 0
    while True:
        hwm = max(hwm, _vm_hwm_kb(pid))
        done, status, ru = os.wait4(pid, os.WNOHANG)
        if done == pid:
            break
        time.sleep(0.01)
    wall = time.perf_counter() - t0
    with open(err_path, encoding="utf-8", errors="replace") as fh:
        err = fh.read()
    rc = os.waitstatus_to_exitcode(status)
    if rc != 0:
        raise SystemExit(f"{argv[0]} exited {rc}\n{err}")
    return Run(wall, ru.ru_utime + ru.ru_stime, hwm, err)


def best_of(argv: list[str], repeat: int, tmp: str,
            before=None) -> Run:
    """Best (lowest) wall clock of `repeat` runs; RSS is the worst seen."""
    runs: list[Run] = []
    for _ in range(repeat):
        if before is not None:
            before()
        runs.append(measure(argv, DEVNULL, os.path.join(tmp, "err.txt")))
    best = min(runs, key=lambda r: r.wall)
    best.rss_kb = max(r.rss_kb for r in runs)
    return best


def sha_of(argv: list[str]) -> str:
    """sha256 of a side's stdout (used only on the small head slice)."""
    proc = subprocess.run(argv, capture_output=True)
    if proc.returncode != 0:
        raise SystemExit(f"{argv[0]} exited {proc.returncode}\n"
                         f"{proc.stderr.decode(errors='replace')}")
    return hashlib.sha256(proc.stdout).hexdigest()


def count_lines(argv: list[str]) -> int:
    """Line count of a side's stdout — an UNTIMED pass (the timed runs write to
    /dev/null so that nothing but the parse work is measured)."""
    n = 0
    with subprocess.Popen(argv, stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL) as proc:
        while True:
            chunk = proc.stdout.read(1 << 20)
            if not chunk:
                break
            n += chunk.count(b"\n")
    return n


# --------------------------------------------------------------------------- #
# corpus synthesis — shapes cloned from tests/parity/fixtures
# --------------------------------------------------------------------------- #
def fixture_records(name: str) -> list[dict]:
    path = os.path.join(FIXTURES, name, "input.jsonl")
    out = []
    with open(path, encoding="utf-8-sig", errors="replace") as fh:
        for line in fh:
            line = line.strip().rstrip(",")
            if not line or line in ("[", "]"):
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue          # fixtures carry deliberate bad lines
            if isinstance(rec, dict):
                out.append(rec)
    return out


HOSTS = [f"WKSTN-{i:02d}" for i in range(1, 13)]
USERS = ["jcloudy", "steve", "insec", "svc_backup", "admin", "jo", "m57"]
IPS = [f"10.10.{a}.{b}" for a in (1, 2, 7) for b in (11, 42, 99, 116, 207)]


def build_evtx(path: str, lines: int, rnd: random.Random) -> int:
    """EvtxECmd JSON export: BOM + `[` + one record per line, as the fixture."""
    templates = fixture_records("core_evtx_security")
    base = datetime.datetime(2019, 1, 28, 19, 40, 32, tzinfo=datetime.timezone.utc)
    written = 0
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("﻿[\n")
        for i in range(lines):
            rec = dict(templates[i % len(templates)])
            rec["EventRecordId"] = 1000 + i
            rec["Computer"] = f"{HOSTS[i % len(HOSTS)]}.example.com"
            rec["TimeCreated"] = (base + datetime.timedelta(
                seconds=i, microseconds=rnd.randrange(1_000_000))).isoformat()
            payload = rec.get("Payload")
            if isinstance(payload, str):
                rec["Payload"] = json.dumps(_mutate_payload(json.loads(payload), i, rnd))
            fh.write(json.dumps(rec))
            fh.write(",\n")
            written += 1
        fh.write("]\n")
    return written


def _mutate_payload(payload: dict, i: int, rnd: random.Random) -> dict:
    """Vary the EventData values an EVTX map actually reads."""
    data = payload.get("EventData", {}).get("Data")
    if not isinstance(data, list):
        return payload
    new = []
    for item in data:
        if not isinstance(item, dict):
            new.append(item)
            continue
        item = dict(item)
        name, text = item.get("@Name"), item.get("#text")
        if isinstance(text, str):
            if name in ("TargetUserName", "SubjectUserName"):
                item["#text"] = USERS[i % len(USERS)]
            elif name in ("TargetDomainName", "WorkstationName"):
                item["#text"] = HOSTS[i % len(HOSTS)]
            elif name in ("TargetLogonId", "SubjectLogonId"):
                item["#text"] = f"0x{0x330000 + i:X}"
            elif name in ("ProcessId", "NewProcessId"):
                item["#text"] = f"0x{rnd.randrange(0x100, 0xFFFF):X}"
            elif name == "IpAddress" and text != "-":
                item["#text"] = IPS[i % len(IPS)]
            elif name.endswith("Sid") and text.startswith("S-1-5"):
                item["#text"] = f"S-1-5-21-1-2-3-{1000 + (i % 500)}"
        new.append(item)
    payload = dict(payload)
    payload["EventData"] = dict(payload["EventData"], Data=new)
    return payload


def build_zeek(path: str, lines: int, rnd: random.Random) -> int:
    """A Zeek conn.json: one connection record per line."""
    templates = fixture_records("zeek_conn")
    base = 1341856211.834184
    with open(path, "w", encoding="utf-8") as fh:
        for i in range(lines):
            rec = dict(templates[i % len(templates)])
            if isinstance(rec.get("ts"), str):
                rec["ts"] = datetime.datetime.fromtimestamp(
                    base + i, datetime.timezone.utc).strftime(
                        "%Y-%m-%dT%H:%M:%S.%fZ")
            elif isinstance(rec.get("ts"), (int, float)):
                rec["ts"] = round(base + i, 6)
            rec["uid"] = f"C{i:010d}xZ"
            rec["id.orig_h"] = IPS[i % len(IPS)]
            rec["id.orig_p"] = 1024 + (i % 60000)
            rec["id.resp_h"] = IPS[(i * 7) % len(IPS)]
            for key in ("orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts"):
                if isinstance(rec.get(key), int):
                    rec[key] = rnd.randrange(0, 100_000)
            fh.write(json.dumps(rec))
            fh.write("\n")
    return lines


# raw log2timeline json_line records: the fixtures' wrapped {Parser, Record}
# rows unwrapped back into what Plaso itself writes (flat record + parser +
# µs timestamp), which is what a raw container holds.
L2T_SOURCES = ["plaso_linux_utmp", "plaso_linux_mft", "plaso_linux_usnjrnl",
               "plaso_linux_filestat", "plaso_linux_text", "plaso_exec_prefetch"]


def _l2t_templates() -> list[dict]:
    out = []
    for name in L2T_SOURCES:
        for row in fixture_records(name):
            inner = row.get("Record")
            if not isinstance(inner, dict):        # a fixture edge row
                continue
            rec = dict(inner)
            rec.setdefault("parser", row.get("Parser") or "unknown")
            out.append(rec)
    return out


def build_l2t_container(path: str, lines: int, rnd: random.Random) -> int:
    """A raw Plaso json_line CONTAINER: many parsers interleaved, plus the
    blank / unparseable lines a real container carries (they still consume a
    physical line number, which is a row's RecordId)."""
    templates = _l2t_templates()
    base_us = 1_600_262_070_462_820
    with open(path, "w", encoding="utf-8") as fh:
        for i in range(lines):
            if i % 5000 == 4999:                    # a blank line
                fh.write("\n")
                continue
            if i % 5000 == 4998:                    # an unparseable line
                fh.write("{not json\n")
                continue
            rec = dict(templates[i % len(templates)])
            rec["timestamp"] = base_us + i * 1_000_000 + rnd.randrange(1_000_000)
            for key in ("hostname", "image_hostname"):
                if isinstance(rec.get(key), str) and rec[key]:
                    rec[key] = HOSTS[i % len(HOSTS)]
            if isinstance(rec.get("username"), str):
                rec["username"] = USERS[i % len(USERS)]
            if isinstance(rec.get("ip_address"), str):
                rec["ip_address"] = IPS[i % len(IPS)]
            if isinstance(rec.get("pid"), int):
                rec["pid"] = rnd.randrange(100, 30000)
            fh.write(json.dumps(rec))
            fh.write("\n")
    return lines


def head_slice(src: str, dst: str, lines: int) -> None:
    """First `lines` lines of a corpus file — BOM and `[` header preserved."""
    with open(src, "rb") as fh_in, open(dst, "wb") as fh_out:
        for i, line in enumerate(fh_in):
            if i >= lines:
                break
            fh_out.write(line)


# --------------------------------------------------------------------------- #
# phases
# --------------------------------------------------------------------------- #
class Row:
    def __init__(self, corpus, records, events, py: Run, go: Run, mib: float):
        self.corpus, self.records, self.events = corpus, records, events
        self.py, self.go, self.mib = py, go, mib

    @property
    def speedup(self) -> float:
        return self.py.wall / self.go.wall if self.go.wall else float("inf")


def bench_parse(label: str, path: str, artefacts: list[str], host: str | None,
                records: int, repeat: int, tmp: str) -> Row:
    slice_path = os.path.join(tmp, "slice." + os.path.basename(path))
    head_slice(path, slice_path, HEAD_SLICE)
    py_sha = sha_of(ref_parse_argv(slice_path, artefacts, host))
    go_sha = sha_of(go_parse_argv(slice_path, artefacts, host))
    if py_sha != go_sha:
        raise SystemExit(f"{label}: the two sides DISAGREE on the head slice "
                         f"({py_sha} vs {go_sha}) — benchmark aborted")
    os.remove(slice_path)

    print(f"  [{label}] head slice byte-identical ({py_sha[:12]}…); timing "
          f"{repeat}x per side", flush=True)
    py = best_of(ref_parse_argv(path, artefacts, host), repeat, tmp)
    go = best_of(go_parse_argv(path, artefacts, host), repeat, tmp)

    events = int(py.stderr.split("EVENTS ", 1)[1].split()[0])
    go_events = count_lines(go_parse_argv(path, artefacts, host))   # untimed
    if go_events != events:
        raise SystemExit(f"{label}: {events} Python events vs {go_events} Go")
    mib = os.path.getsize(path) / (1 << 20)
    return Row(label, records, events, py, go, mib)


def bench_split(label: str, path: str, records: int, repeat: int,
                tmp: str) -> tuple[Row, str]:
    """Time both splitters; leave the Go split on disk for the table phase."""
    slice_path = os.path.join(tmp, "slice.container.jsonl")
    head_slice(path, slice_path, HEAD_SLICE)
    py_dir, go_dir = os.path.join(tmp, "slice_py"), os.path.join(tmp, "slice_go")
    for d in (py_dir, go_dir):
        shutil.rmtree(d, ignore_errors=True)
        os.makedirs(d)
    subprocess.run(ref_split_argv(slice_path, py_dir), check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(go_split_argv(slice_path, go_dir), check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    names = sorted(os.listdir(py_dir))
    if names != sorted(os.listdir(go_dir)):
        raise SystemExit(f"{label}: different table files on the head slice")
    for name in names:
        with open(os.path.join(py_dir, name), "rb") as a, \
             open(os.path.join(go_dir, name), "rb") as b:
            if a.read() != b.read():
                raise SystemExit(f"{label}: {name} differs on the head slice")
    for d in (py_dir, go_dir):
        shutil.rmtree(d)
    os.remove(slice_path)
    print(f"  [{label}] head slice byte-identical ({len(names)} tables); timing "
          f"{repeat}x per side", flush=True)

    py_out, go_out = os.path.join(tmp, "split_py"), os.path.join(tmp, "split_go")

    def fresh(d):
        shutil.rmtree(d, ignore_errors=True)
        os.makedirs(d)

    py = best_of(ref_split_argv(path, py_out), repeat, tmp,
                 before=lambda: fresh(py_out))
    tables = len(os.listdir(py_out))
    shutil.rmtree(py_out)                       # disk: one split at a time
    go = best_of(go_split_argv(path, go_out), repeat, tmp,
                 before=lambda: fresh(go_out))
    mib = os.path.getsize(path) / (1 << 20)
    return Row(label, records, tables, py, go, mib), go_out


# --------------------------------------------------------------------------- #
# reporting
# --------------------------------------------------------------------------- #
def host_line() -> str:
    cpu = ""
    try:
        with open("/proc/cpuinfo", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("model name"):
                    cpu = line.split(":", 1)[1].strip()
                    break
    except OSError:
        pass
    go_ver = "?"
    try:
        go_ver = subprocess.run(["go", "version"], capture_output=True,
                                text=True).stdout.strip()
        go_ver = go_ver.split()[2] if go_ver else "?"
    except OSError:
        pass
    return (f"{cpu or platform.processor() or 'unknown CPU'}, "
            f"{os.cpu_count()} vCPU · {platform.system()} "
            f"{platform.release()} · CPython {platform.python_version()} · "
            f"{go_ver}")


def markdown(rows: list[Row]) -> str:
    out = ["| corpus | input | records | events | Python wall (cpu) | "
           "Go wall (cpu) | wall speed-up | peak RSS py / go |",
           "| --- | --- | --- | --- | --- | --- | --- | --- |"]
    for r in rows:
        out.append(
            f"| {r.corpus} | {r.mib:.0f} MiB | {r.records:,} | {r.events:,} | "
            f"{r.py.wall:.2f} s ({r.py.cpu:.2f}) | "
            f"{r.go.wall:.2f} s ({r.go.cpu:.2f}) | **{r.speedup:.2f}x** | "
            f"{r.py.rss_kb / 1024:.1f} / {r.go.rss_kb / 1024:.1f} MiB |")
    return "\n".join(out)


def plain(rows: list[Row]) -> str:
    head = (f"{'corpus':<40}{'records':>10}{'events':>10}"
            f"{'py wall':>10}{'go wall':>9}{'speedup':>9}"
            f"{'py/go cpu s':>16}{'py/go rss MiB':>16}")
    out = [head, "-" * len(head)]
    for r in rows:
        out.append(f"{r.corpus:<40}{r.records:>10,}{r.events:>10,}"
                   f"{r.py.wall:>9.2f}s{r.go.wall:>8.2f}s{r.speedup:>8.2f}x"
                   f"{r.py.cpu:>10.2f}/{r.go.cpu:<5.2f}"
                   f"{r.py.rss_kb / 1024:>10.1f}/{r.go.rss_kb / 1024:<5.1f}")
    return "\n".join(out)


# --------------------------------------------------------------------------- #
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--workdir", help="corpus directory (default: a temp dir); "
                                      "deleted at the end unless --keep")
    ap.add_argument("--scale", type=float, default=1.0,
                    help="multiply every corpus size (default 1.0 = "
                         f"{EVTX_LINES:,}/{L2T_LINES:,}/{ZEEK_LINES:,} lines)")
    ap.add_argument("--repeat", type=int, default=3,
                    help="timed runs per side; the best wall clock wins")
    ap.add_argument("--keep", action="store_true", help="keep the corpus")
    ap.add_argument("--seed", type=int, default=20260912)
    # worker modes (this script re-invokes itself as the Python reference side)
    ap.add_argument("--worker", choices=("parse", "split"),
                    help=argparse.SUPPRESS)
    ap.add_argument("--in", dest="in_path", help=argparse.SUPPRESS)
    ap.add_argument("--artefacts", help=argparse.SUPPRESS)
    ap.add_argument("--host", help=argparse.SUPPRESS)
    ap.add_argument("--out-dir", dest="out_dir", help=argparse.SUPPRESS)
    args = ap.parse_args(argv)

    if args.worker == "parse":
        return worker_parse(args.in_path,
                            [a for a in args.artefacts.split(",") if a],
                            args.host)
    if args.worker == "split":
        return worker_split(args.in_path, args.out_dir)

    if not os.path.isfile(GO_BIN):
        raise SystemExit(f"{GO_BIN} not found — build it with: make -C go build")

    workdir = args.workdir or os.path.join(
        os.environ.get("TMPDIR", "/tmp"), f"byakugan-bench-{os.getpid()}")
    os.makedirs(workdir, exist_ok=True)
    rnd = random.Random(args.seed)
    n_evtx = max(1, int(EVTX_LINES * args.scale))
    n_l2t = max(1, int(L2T_LINES * args.scale))
    n_zeek = max(1, int(ZEEK_LINES * args.scale))

    print(f"host: {host_line()}")
    print(f"corpus: {workdir} (scale {args.scale}, repeat {args.repeat})\n")
    rows: list[Row] = []
    try:
        # 1. EvtxECmd Security export -------------------------------------- #
        path = os.path.join(workdir, "Security_EvtxECmd_Output.json")
        print(f"synthesising {n_evtx:,}-record EvtxECmd export…", flush=True)
        build_evtx(path, n_evtx, rnd)
        rows.append(bench_parse("EvtxECmd Security -> evtx_security", path,
                                ["evtx_security"], None, n_evtx, args.repeat,
                                workdir))
        os.remove(path)                                   # disk, phase by phase

        # 2. Zeek conn.json ------------------------------------------------- #
        path = os.path.join(workdir, "conn.json")
        print(f"synthesising {n_zeek:,}-record Zeek conn.json…", flush=True)
        build_zeek(path, n_zeek, rnd)
        rows.append(bench_parse("Zeek conn.json -> zeek_conn", path,
                                ["zeek_conn"], "capture1", n_zeek, args.repeat,
                                workdir))
        os.remove(path)

        # 3. raw log2timeline container: split, then parse a split table ---- #
        path = os.path.join(workdir, "image.jsonl")
        print(f"synthesising {n_l2t:,}-line raw l2t container…", flush=True)
        build_l2t_container(path, n_l2t, rnd)
        row, go_dir = bench_split("raw l2t container -> split-l2t", path,
                                  n_l2t, args.repeat, workdir)
        rows.append(row)
        os.remove(path)

        from byakugan import pipeline                      # noqa: PLC0415
        table = max((os.path.join(go_dir, n) for n in os.listdir(go_dir)),
                    key=os.path.getsize)
        arts = pipeline.route(table)                       # the LIVE routing
        n_rows = sum(1 for _ in open(table, encoding="utf-8", errors="replace"))
        rows.append(bench_parse(
            f"l2t {os.path.basename(table).split('.')[-1]} table -> "
            f"{','.join(arts)}", table, arts, "image", n_rows, args.repeat,
            workdir))
        shutil.rmtree(go_dir)
    finally:
        if args.keep:
            print(f"\ncorpus kept: {workdir}")
        else:
            shutil.rmtree(workdir, ignore_errors=True)

    print("\n" + plain(rows) + "\n")
    print(markdown(rows))
    print(f"\nhost: {host_line()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
