# Changelog

All notable changes to flawed are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.7.2] - 2026-06-07

### Added

- Published to PyPI: install with `pip install flawed` (or `uv pip install flawed`).

This release carries no functional changes from 0.7.1; it establishes automated
PyPI publishing via GitHub Actions trusted publishing.

## [0.7.1] - 2026-05-30

### Fixed

- Config override-merge no longer drops fields: applying a matching `overrides`
  block previously reset `timeouts` and `cache_invalidation` to their defaults;
  all sections now round-trip through override resolution.
- `ResolvedConfig` data/state directories are XDG-aware, honouring
  `$XDG_DATA_HOME`/`$XDG_STATE_HOME` rather than writing under the home directory.
- Value-flow construction fails closed on a memory budget: a pathological graph
  that could previously be OS-killed (a silent zero) now emits an honest
  `VALUE_FLOW_INCOMPLETE` gap instead.

## [0.7.0] - 2026-05-23

### Added

- Command-line scanner: `flawed scan` over a repository with human-readable text,
  `--json`, and SARIF 2.1.0 output, plus `rules`, `explain`, `explore`,
  `inspect`, `providers`, `config`, and `version` subcommands.
- Rule selection: `--rules-dir` (repeatable), id globs (`-i`/`-e`), regex
  (`-I`/`-E`), and a `--smoke` subset for quick iteration.
- Severity gating and CI integration: `--fail-on`, `--min-severity`, stable exit
  codes, and a stdout/stderr split (findings vs diagnostics).
- Incremental scanning: `--baseline-commit`/`--baseline` diffing on
  location-stable keys, `.flawedignore`, inline `# flawed: ignore` directives,
  and `--strict`.
- `load_findings()` and `flawed explore` for querying a completed scan's results.
- Per-repository result cache (`flawed cache status|clear`) keyed by content hash.
- Always-on local scan record (`runs.jsonl` plus a per-repo `scan_metrics.jsonl`),
  written locally with no network or telemetry; opt out with
  `observability_enabled: false`.
- Additional framework providers, and contributor/agent-assistant guidance.

### Changed

- Layer 1 indices now carry an explicit schema version, so cached indices stay
  valid across releases that do not change the index format.

## [0.6.0] - 2026-03-28

Initial public release — flawed as a Python library.

### Added

- Three-layer engine with `import-linter`-enforced boundaries: a Code Index (L1:
  AST, control-flow graphs, an AST-based call graph, value-flow edges, symbols,
  and resolved types), a framework-aware Semantic layer (L2), and a typed
  Rule API (L3).
- Python API: `open_repo()` builds (or loads a cached) model of a repository and
  exposes immutable, chainable collections for interactive exploration.
- Framework-aware model: routes, typed request inputs, scoped state effects,
  security checks/guards, conditions and control-flow views, interprocedural
  value flow along the call graph, and type-disagreement signals.
- Flask provider recognition: authentication/authorization guards (`flask_login`,
  Flask-HTTPAuth, flask-allows), WTForms validation, and session/`g` identity
  values, so guarded and validated routes are credited rather than flagged.
- Five generic capability-demo rules — endpoint inventory, request-input
  inventory, route-guard inventory, value-flow trace, and type-disagreement
  survey — written against the same Rule API custom rules use.
- Sound by design: code that cannot be analysed surfaces an explicit
  `AnalysisGap` rather than being silently skipped, and value-flow answers are
  conservative (a negative means "not proven", never "provably safe").
- Per-repository Layer 1 index caching, so repeat runs skip extraction.

[0.7.2]: https://github.com/execveat/flawed/releases/tag/v0.7.2
[0.7.1]: https://github.com/execveat/flawed/releases/tag/v0.7.1
[0.7.0]: https://github.com/execveat/flawed/releases/tag/v0.7.0
[0.6.0]: https://github.com/execveat/flawed/releases/tag/v0.6.0
