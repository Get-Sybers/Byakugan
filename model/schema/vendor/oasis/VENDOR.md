# Vendored OASIS STIX 2.1 JSON schemas — byte-verbatim

- generated_from: https://github.com/oasis-open/cti-stix2-json-schemas
- commit: 9af1db41b7b86c06324f899649ae83480134f66e (2026-01-19)
- contents: `common/`, `sdos/`, `scos` (as `observables/`), `sros/` — copied
  verbatim, never edited (informative per STIX 2.1 §1.2.12; the vendored
  spec at docs/standards/ is normative). Byakugan schemas compose these
  under `allOf` with `unevaluatedProperties: false` at the composed root —
  the overlay carries every byakugan-declared property; these files are
  never forked.
