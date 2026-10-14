<!-- The title becomes the squash commit: `type(scope): summary` (Conventional Commits). -->

## What and why

<!-- What changes, and the reasoning that is not in the diff. -->

## Checklist

- [ ] `pytest -q` and `make -C go build test lint` are green locally (the same gate CI runs)
- [ ] `CHANGELOG.md` has an entry under `## [Unreleased]` (Keep a Changelog)
- [ ] A model or projection change re-renders `elastic/` and `go/internal/ir/ir.json` (the drift checks gate it)
- [ ] No evidence, credentials or generated output is committed
- [ ] Documentation (`README.md`, `docs/`) matches the behaviour
