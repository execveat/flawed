# flawed

A static-analysis engine for Python web applications. flawed builds a
framework-aware model of a Python web app — its routes, request inputs, state
effects, call graph, and value flow — and exposes that model as a Python library.

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

It returns immutable, chainable collections (`group_by` / `count_by` /
`tabulate` / `|` / slicing). See [Python API](docs/python-api.md) for the full
surface.

## Documentation

End-user docs live in [`docs/`](docs/):

- **[Writing rules](docs/writing-rules.md)** — the rule-authoring guide: the
  `@detector` contract and the objects a rule navigates.
- **[The analysis model](docs/analysis-model.md)** — what the engine models
  (routes, inputs, effects, call graph, value flow) and how to think about it.
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
mise run check                 # full gate: lockfile + lint + format + mypy + layers + framework/dep checks + tests
mise run check -- PATH...      # scope the gate to specific files or directories
mise run test                  # run affected tests (testmon)
mise run test -- tests/unit/   # scope tests to a directory or file
```

The pre-commit hook is tracked at `tools/hooks/pre-commit`; `mise run
install-hooks` copies it into the repository's git hooks directory (idempotent,
and worktree-aware).

## License

flawed is released under the [Apache License 2.0](LICENSE).
