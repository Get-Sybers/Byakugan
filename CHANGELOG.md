# Changelog

All notable changes are documented here, following
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- The repository-level pieces of the get-sybers standard (DX_DFIR
  `docs/reference/build-and-test.md`): golangci-lint v2 over the Go engine
  (`.golangci.yml`, `make -C go lint`) in the `lint-and-test` workflow, with
  `all_green` as the one required status check; Dependabot (actions, the Go
  module and the Python inventory, weekly, grouped); `CODEOWNERS`, a security
  policy, a pull-request template, `.editorconfig` and `.gitattributes`.

### Changed
- The workflows run with a read-only token that is never persisted in the
  checkout, and superseded runs of the same ref are cancelled.

### Fixed
- The findings the new Go lint surfaced, none of which changes behaviour:
  `errors.As` for the `*strconv.NumError` check; the two `ir.json` writer
  calls explicitly discarded; a test local that shadowed the `max` builtin
  renamed; `d.i++`; a redundant nil check; comment spellings.

## [0.2.1] - 2026-10-03

The last release before this changelog was started; see the git history for
this and the earlier tags.

## [0.2.0] - 2026-10-03

## [0.1.0] - 2026-08-30

[Unreleased]: https://github.com/Get-Sybers/Byakugan/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/Get-Sybers/Byakugan/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/Get-Sybers/Byakugan/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Get-Sybers/Byakugan/releases/tag/v0.1.0
