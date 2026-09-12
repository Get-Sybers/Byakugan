"""The requirements files and pyproject.toml cannot drift apart.

Dependency tracing is only worth anything if the traced inventory is the one
that is actually installed. Two places declare Byakugan's Python dependencies —
`pyproject.toml` (what `pip install byakugan` resolves) and `requirements.txt` /
`requirements-dev.txt` (what a pinned environment installs) — so these tests
hold them to each other:

* the RUNTIME set must be identical, package AND version range: adding,
  dropping or re-ranging a dependency in one file only fails here;
* the DEV set must hold the same packages as the `dev` extra, with every exact
  pin satisfying the floor the extra declares (the extra stays loose for
  contributors; the requirements file is the reproducible pin).

The Go side has no equivalent test: `go/go.mod` IS the Go requirements file and
it is stdlib-only (no `require` block, no go.sum) — `make -C go build` on a
network-less machine is that proof.
"""
from __future__ import annotations

import os
import re

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# name[extras] followed by the version specifier, e.g. "pyyaml>=6", "pytest==9.1.1"
_REQ = re.compile(r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?"
                  r"(?P<spec>.*)$")


def _canon(name: str) -> str:
    """PEP 503 normalisation — PyYAML, pyyaml and py_yaml are one package."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _parse(requirement: str) -> tuple[str, str]:
    m = _REQ.match(requirement.strip())
    assert m, f"unparseable requirement: {requirement!r}"
    return _canon(m.group("name")), m.group("spec").replace(" ", "")


def _requirements(filename: str) -> dict[str, str]:
    """{package: version specifier} from a requirements file (comments, blank
    lines and `-r` includes skipped)."""
    out: dict[str, str] = {}
    with open(os.path.join(REPO, filename), encoding="utf-8") as fh:
        for line in fh:
            line = line.split("#", 1)[0].strip()
            if not line or line.startswith("-"):
                continue
            name, spec = _parse(line)
            assert name not in out, f"{filename}: {name} listed twice"
            out[name] = spec
    return out


def _pyproject() -> dict:
    try:
        import tomllib                                   # noqa: PLC0415
    except ModuleNotFoundError:                          # Python 3.10
        tomllib = pytest.importorskip(
            "tomli", reason="no TOML reader (Python < 3.11 without tomli)")
    with open(os.path.join(REPO, "pyproject.toml"), "rb") as fh:
        return tomllib.load(fh)


def _version(spec: str) -> tuple[int, ...]:
    """The numeric version out of a single specifier ('==9.1.1' -> (9, 1, 1))."""
    digits = re.search(r"(\d+(?:\.\d+)*)", spec)
    assert digits, f"no version in specifier {spec!r}"
    return tuple(int(p) for p in digits.group(1).split("."))


def test_runtime_requirements_match_pyproject():
    """requirements.txt IS pyproject's [project] dependencies."""
    declared = dict(_parse(r) for r in _pyproject()["project"]["dependencies"])
    assert _requirements("requirements.txt") == declared, (
        "requirements.txt and pyproject.toml [project] dependencies disagree — "
        "edit BOTH (see the header of requirements.txt)")


def test_dev_requirements_cover_the_dev_extra():
    """requirements-dev.txt holds the dev extra's packages, exactly pinned."""
    extra = dict(_parse(r) for r in
                 _pyproject()["project"]["optional-dependencies"]["dev"])
    dev = _requirements("requirements-dev.txt")
    assert set(dev) == set(extra), (
        "requirements-dev.txt and pyproject.toml's dev extra hold different "
        "packages")
    for name, spec in dev.items():
        assert spec.startswith("=="), (
            f"{name}: the dev file pins exact versions (got {spec!r})")
        floor = extra[name]
        assert floor.startswith(">="), (
            f"{name}: the dev extra should declare a floor (got {floor!r})")
        assert _version(spec) >= _version(floor), (
            f"{name}: pinned {spec} is below the dev extra's floor {floor}")


def test_dev_requirements_include_the_runtime_file():
    """`pip install -r requirements-dev.txt` must also bring the runtime deps."""
    with open(os.path.join(REPO, "requirements-dev.txt"), encoding="utf-8") as fh:
        body = fh.read()
    assert re.search(r"^-r\s+requirements\.txt\s*$", body, re.M), (
        "requirements-dev.txt must include `-r requirements.txt`")


def test_go_module_is_stdlib_only():
    """go/go.mod is the Go requirements file — no third-party modules, so no
    go.sum. If this ever fails, go/README.md's dependency section is stale."""
    with open(os.path.join(REPO, "go", "go.mod"), encoding="utf-8") as fh:
        body = fh.read()
    assert "require" not in body, (
        "go/go.mod now requires a third-party module — update go/README.md's "
        "Dependencies section (and CI's `cache: false` note)")
    assert not os.path.exists(os.path.join(REPO, "go", "go.sum")), (
        "go.sum appeared — the Go engine is no longer stdlib-only")
