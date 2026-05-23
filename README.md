# flawed

A static-analysis engine for Python web applications. flawed builds a
framework-aware model of a Python web app — its routes, request inputs, state
effects, call graph, and value flow — and exposes that model as a Python library
and a command-line tool.

## Python API

The top-level `flawed` package is the analysis API — the same surface the
bundled rules are built on, usable directly from a REPL or a script.
`open_repo()` loads a repository's model:

```python
from flawed import open_repo
from flawed.route import POST

repo = open_repo("path/to/app")          # build (or load cached) the model
repo.routes                              # RouteCollection(75) [Route(GET / → index, …), …]
repo.routes.count_by(lambda r: "/".join(sorted(m.name for m in r.methods)))
                                         # Counter({'GET': 35, 'POST': 28, 'GET/POST': 12, ...})

# Which POST routes write state but declare no guard in their handler stack?
for route in repo.routes.accepting(POST):
    if route.reachable.effects() and not route.full_stack.checks():
        print(route)
```

`load_findings()` is its mirror image — comb through a scan you already ran:

```python
from flawed import load_findings

findings = load_findings("scan.json")               # a --json or --sarif capture
findings.count_by("rule_id").most_common(5)         # which rules fired most
findings.min_severity("high").in_dir("auth/")       # high-sev findings under auth/
findings.diff(load_findings("baseline.json")).added # new findings vs a baseline
```

Both return immutable, chainable collections (`group_by` / `count_by` /
`tabulate` / `|` / slicing). See [Python API](docs/python-api.md) for the full
surface.

## Command line

flawed is also a command-line scanner that runs rule modules over a repository:

```bash
flawed                       # orientation dashboard (does not scan)
flawed .                     # scan the current directory
flawed scan path/to/repo     # scan a repository: L1 index + L2 semantic + L3 rules
flawed scan . --rules-dir ./my_rules   # run your own rule modules instead of the built-ins
```

Findings stream to **stdout**, progress and diagnostics to **stderr**. See
[CLI](docs/cli.md) for output formats (`--json`, `--sarif`), exit codes,
baseline diffing, and the full command list.

## Documentation

End-user docs live in [`docs/`](docs/):

- **[Writing rules](docs/writing-rules.md)** — the rule-authoring guide: the
  `@detector` contract, the objects a rule navigates, and running your own rules
  with `--rules-dir`.
- **[The analysis model](docs/analysis-model.md)** — what the engine models
  (routes, inputs, effects, call graph, value flow) and how to think about it.
- **[CLI](docs/cli.md)** — running scans, output formats, and configuration.
- **[Python API](docs/python-api.md)** — querying the model interactively from a
  REPL or script.
- **[Provider authoring](docs/provider-authoring.md)** — teaching the engine a
  new framework so your rules see its routes, inputs, and effects.

## Setup

flawed uses `mise` for project tools and task entry points, and `uv` for Python
dependency resolution.

```bash
mise install   # Python + uv, pinned in mise.toml
mise deps      # uv sync --all-extras
```

### Development

```bash
mise run install-hooks         # install the version-controlled pre-commit gate
mise run check                 # full gate: lockfile + lint + format + mypy + layers + framework/dep/subprocess checks + tests
mise run check -- PATH...      # scope the gate to specific files or directories
mise run test                  # run affected tests (testmon)
mise run test -- tests/unit/   # scope tests to a directory or file
```

The pre-commit hook is tracked at `tools/hooks/pre-commit`; `mise run
install-hooks` copies it into the repository's git hooks directory (idempotent,
and worktree-aware). Edit the tracked file and reinstall — never edit the copy
under `.git/hooks/` directly.

## Configuration

Global config: `~/.config/flawed/config.yaml`

```yaml
data_dir: <path>          # where L1 cache artifacts are stored
repo_local: false         # true = store cache next to each repo
observability_enabled: true   # local run/scan metrics; set false to opt out
type_enrichment:
  enable_mypy_batch: false  # opt-in experimental mypy oracle
```

By default each scan appends local observability records — a `runs.jsonl` plus a
per-repo `scan_metrics.jsonl` under the data dir. These are written **locally
only** (no network, no telemetry); set `observability_enabled: false` to turn
them off.

Per-repo cache uses `<data_dir>/owner__name/` layout. The index is cached after
the first run; subsequent scans skip L1 extraction.

## License

flawed is released under the [Apache License 2.0](LICENSE).
