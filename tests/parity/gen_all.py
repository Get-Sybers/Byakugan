"""Run every per-family parity generator under tests/parity/genf/.

There is exactly ONE way to (re)generate the family vectors and fixtures: the
family's own script. This runner exists so a human (or CI) can rebuild them
all at once without touching any of them:

    python tests/parity/gen_all.py            # every family
    python tests/parity/gen_all.py core zeek_conn   # just those

Each script is run in its own interpreter, in sorted order, so one family's
failure names itself and cannot corrupt another's output. The engine-wide
vector generators (gen_pyjson_vectors.py, gen_pyre_vectors.py,
gen_reader_vectors.py, gen_spindle_vectors.py) are NOT family-scoped and are
not run from here — they are shared files, run them explicitly.
"""
from __future__ import annotations

import glob
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
GENF = os.path.join(HERE, "genf")


def family_scripts(only: list[str] | None = None) -> list[str]:
    paths = sorted(p for p in glob.glob(os.path.join(GENF, "*.py"))
                   if not os.path.basename(p).startswith("_"))
    if only:
        by_name = {os.path.basename(p)[:-3]: p for p in paths}
        missing = [n for n in only if n not in by_name]
        if missing:
            raise SystemExit(f"no such family generator(s): {', '.join(missing)}\n"
                             f"available: {', '.join(sorted(by_name))}")
        return [by_name[n] for n in only]
    return paths


def main(argv: list[str]) -> int:
    scripts = family_scripts(argv or None)
    if not scripts:
        print(f"no family generators found under {GENF}", file=sys.stderr)
        return 1
    failed = []
    for path in scripts:
        name = os.path.basename(path)[:-3]
        print(f"=== genf/{name}.py ===")
        proc = subprocess.run([sys.executable, path])
        if proc.returncode != 0:
            failed.append(name)
    if failed:
        print(f"FAILED: {', '.join(failed)}", file=sys.stderr)
        return 1
    print(f"{len(scripts)} family generator(s) OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
