# Agent Quick Start

flawed is a static-analysis engine for Python codebases — a framework-aware
model of a Python web app (routes, inputs, effects, call graph, value flow)
with a rule API and CLI. See `.claude/CLAUDE.md` for full context.

## Conventions

- Orient first: `git status` && `git log --oneline -5`.
- Run tests with `mise run test` — never `pytest` directly (a hook blocks it).
- Quality gate: `mise run check` (lint, format, types, layers, tests); scope it
  with `mise run check -- PATH...`.
- Intermediate scratch files go in `local/` (gitignored).

## Docs

- Writing rules (detector API): `docs/writing-rules.md`
- Analysis model (control/data flow): `docs/analysis-model.md`
- CLI usage: `docs/cli.md`
- Python API: `docs/python-api.md`
- Provider authoring: `docs/provider-authoring.md`
