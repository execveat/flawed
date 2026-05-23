# Writing rules

A rule is a small Python function that walks the model `flawed` builds of a
codebase and yields findings. This guide is the rule author's reference: the
detector contract, the objects you navigate, and how to run your own rules.

You write rules against the top-level `flawed` package — the same surface the
bundled rules are built on. For the conceptual model underneath it (routes,
inputs, effects, call graph, value flow), see [analysis-model.md](analysis-model.md).

---

## The smallest rule

A rule is a generator function decorated with `@detector`. It receives a
`RepoView` and yields `Finding` objects:

```python
from collections.abc import Iterator

from flawed import detector
from flawed.evidence import Finding
from flawed.repo import RepoView
from flawed.severity import Severity


@detector(
    "endpoints",
    severity=Severity.INFO,
    description="Inventory of the HTTP endpoints reconstructed from the codebase",
)
def detect(kb: RepoView) -> Iterator[Finding]:
    for route in kb.routes:
        methods = ", ".join(sorted(m.value for m in route.methods)) or "(unspecified)"
        yield route.finding(
            f"{route.endpoint}: {methods} {route.url_rule} -> {route.handler.fqn}"
        ).evidence(route.handler, "handler function")
```

This is the bundled `endpoints` rule (`src/flawed/_rules/endpoints.py`). The
five rules under `src/flawed/_rules/` are deliberately small, neutral capability
demos — read them as worked examples; they cover the main query surfaces.

### The decorator

```python
@detector(id, *, severity=Severity.INFO, description="...")
```

- **`id`** — a stable rule id. Ids are separator-insensitive for
  `--include`/`--exclude` (`my-rule` ≡ `my_rule`); by convention the `@detector`
  id uses hyphens and the filename uses underscores.
- **`severity`** — a `Severity` (`INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
- **`description`** — one line shown by `flawed explain` and `flawed rules`.

A module is a rule **iff** it carries an `@detector`. Discovery is by decorator,
not filename, so rule modules and plain helpers coexist in one directory.

---

## The entry point: `RepoView`

`kb` is a `RepoView` — the single entry point for navigation. The collections it
exposes:

```python
kb.routes        # RouteCollection — every identified HTTP endpoint
kb.functions     # FunctionCollection — every function
kb.classes       # ClassCollection — every class
kb.type_disagreements   # expressions two type engines typed differently
kb.trace_flow(source_loc, sink_loc)   # on-demand data-flow trace
```

Collections are immutable and chainable — `.where(predicate)`, `.first()`,
`.one()`, and per-type filters like `kb.routes.accepting(POST)` or
`kb.functions.named("login")`. Filtering returns a new collection.

---

## Worked examples

Each bundled rule demonstrates one query surface:

| Rule | Capability shown |
|------|------------------|
| `endpoints` | route reconstruction: `kb.routes`, `route.endpoint/url_rule/methods/handler` |
| `request-inputs` | request-input modelling: `scope.reads()` and the typed `InputSource` of each read |
| `route-guards` | provider-modelled checks: `scope.checks()` over the full request stack |
| `value-flow` | cross-procedure value flow: `scope.effects()` + `scope.reads_flowing_to(target)` |
| `type-disagreements` | the type-disagreement signal: `kb.type_disagreements` |

For example, `value-flow` (`src/flawed/_rules/value_flow.py`) reports where a
request value reaches an operation:

```python
@detector("value-flow", severity=Severity.INFO, description="...")
def detect(kb: RepoView) -> Iterator[Finding]:
    for route in kb.routes:
        scope = route.reachable
        for effect in scope.effects():
            if effect.target is None:
                continue
            feeders = list(scope.reads_flowing_to(effect.target))
            if not feeders:
                continue
            read = feeders[0]
            op = effect.category.name.lower()
            yield (
                route.finding(f"{route.endpoint}: a request value reaches a {op} operation")
                .evidence(read, f"request input: {read.expression}")
                .evidence(effect, f"{op}: {effect.expression}")
            )
```

---

## Detector forms

Most rules iterate routes, but the model supports three shapes:

**Per-route** — the common case (above): iterate `kb.routes`, query each route's
scope.

**Repo-wide** — audit cross-route or whole-repo structure:

```python
@detector("writes-without-a-guard")
def detect(kb: RepoView) -> Iterator[Finding]:
    from flawed.route import POST, accepting
    for route in kb.routes.where(accepting(POST)):
        if route.reachable.effects() and not route.full_stack.checks():
            yield route.finding("POST route writes state with no modelled guard")
```

**Cross-layer** — examine the full request stack including lifecycle hooks and
middleware via `route.full_stack` (see scopes below).

---

## Scopes: choosing how far analysis reaches

Every question about *what happens in code* — reads, effects, conditions, calls
— goes through a `CodeScope`. The scope you pick decides how far the analysis
travels:

| Scope | Includes |
|-------|----------|
| `route.body` / `fn.body` | the direct function body only |
| `route.reachable` / `fn.reachable` | body + all transitively called functions |
| `route.full_stack` | reachable + lifecycle hooks and middleware |
| `cond.true_branch` / `cond.false_branch` | code reachable in one branch of a condition |

Body scope is intra-function; `reachable`/`full_stack` are interprocedural
(call-graph-gated, cross-file).

### Scope query methods

| Method | Returns |
|--------|---------|
| `reads(source=...)` | request `InputRead`s, optionally filtered by source |
| `effects(selector=...)` | `Effect`s matching a selector |
| `checks(category=None)` | provider-declared security checks |
| `conditions()` / `conditions_using(value)` | branch tests (`if`/`while`/ternary) |
| `predicates()` | predicate expressions produced as *values*, not branch tests |
| `calls(selector)` | call sites matching a selector |
| `decorators()` | decorators on functions in scope |
| `exception_guards()` | `try/except` guard patterns |
| `cfg` | a `ControlFlowView` for ordering/dominance queries |

`scope.cfg` answers ordering questions: `cfg.dominates(a, b)` (every path to `b`
passes through `a`) and `cfg.precedes(a, b)` (`a` runs before `b` on all paths).
When the CFG is unavailable both return `False` conservatively and record an
`AnalysisGap`.

---

## Selectors

Reads, effects, and checks are selected with composable, typed selectors.

### Input sources

`scope.reads(source)` filters by where the value came from:

| Source | Constructor |
|--------|-------------|
| Query string | `Query(key="user_id")` |
| Form body | `Form(key="amount")` |
| JSON body | `Json(path="$.id")` |
| Header | `Header(name="X-Api-Key")` |
| Cookie | `Cookie(name="session")` |
| Path parameter | `PathParam(name="id")` |
| File upload | `FileUpload(field="avatar")` |
| Raw body | `RawBody()` |
| Any container with a key | `AnyContainer(key="id")` |
| Union of sources | `AnyOf(sources=(Form(), Json()))` |

A source with no field (e.g. `Query()`) matches any read from that container.
Server-side session access is modelled as a **state effect**
(`STATE_READ`/`STATE_WRITE`, scope `SESSION`), not an input source — session
data is not directly attacker-controlled.

### Effects

`scope.effects(selector)` selects modelled side effects. The taxonomy
(`EffectCategory`) covers `DB_WRITE`, `DB_DELETE`, `DB_READ`, `FILE_WRITE`,
`FILE_READ`, `STATE_WRITE`, `STATE_READ`, `CONFIG_WRITE`, `OUTBOUND_REQUEST`,
`NOTIFICATION`. Query with the sugar namespaces from `flawed.effects`:

```python
from flawed.effects import Db, Data, Mutation, State, Config, Outbound

Db.write()                         # DB_WRITE
Data.write()                       # DB_WRITE | FILE_WRITE
Mutation.any()                     # all state-changing operations
State.write(scope=SESSION)         # session-scoped writes only
State.write(key="user_id")         # writes to a specific state key
route.reachable.effects(Data.write() | State.write())   # compose with |
```

State effects carry a `StateScope` (`REQUEST`, `SESSION`, `SERVER`) describing
persistence lifetime, and a `key` when determinable. Each `Effect` exposes
`.target` (what is written to) and `.value` (what is written) as value handles.

### Checks

`scope.checks(category=None)` returns provider-declared security checks
(authentication, authorization, CSRF, schema validation, rate limiting, …),
labelled by the active provider. Separately, `flawed.checks` offers name/FQN
selectors for raw call sites:

```python
from flawed.checks import Crypto, Token, Schema, Permission

Crypto.compare()    # hmac.compare_digest, check_password_hash, …
Token.verify()      # jwt.decode, itsdangerous loads, …
Schema.validate()   # pydantic, marshmallow, wtforms, …
validators = route.reachable.calls(Crypto.compare() | Token.verify())
```

---

## Value flow

A `ValueHandle` tracks how a value propagates. It is available on
`InputRead.value`, `Effect.target`, `Effect.value`, `CallSite.return_value`,
`Argument.value`, and `Condition.left`/`.right`.

```python
read.value.flows_to(effect.target)        # does this read reach the effect?
effect.target.derived_from(PathParam())    # was the target derived from a path param?
scope.reads_flowing_to(effect.target)      # which reads in scope reach the target
```

All flow queries are **conservative**: `flows_to` / `derived_from` return `True`
only when the flow is *proven*, and `False` when it cannot be proven (not "when
it provably does not exist"). They never return `True` incorrectly. Unknown flow
is treated as unproven, never as safe — consistent with the engine's no-fail-open
stance. See [analysis-model.md](analysis-model.md) for how flow is computed and
why reach depends on the scope you query from.

---

## Building findings

Per-route rules start a finding from the route and attach evidence:

```python
route.finding("summary text").evidence(obj, "why this object matters")
```

`.evidence(...)` accepts any located domain object (a read, effect, check,
handler, condition, …) and a label; chain it to build an evidence trail. For
findings not anchored to a route, construct a `Finding` directly:

```python
from flawed.evidence import Finding

Finding(
    route_endpoint=label,          # or a containing-scope label
    summary="...",
    location=obj.location,
).evidence(obj, "...")
```

`type-disagreements` (`src/flawed/_rules/type_disagreements.py`) is the worked
example of a non-route finding.

---

## Domain object reference

Compact field/method summary of the objects rules navigate most. Full detail
lives in the type contracts under `src/flawed/`.

**`Route`** — `endpoint`, `url_rule`, `methods`, `handler` (a `Function`),
`group`, `location`; `.body` / `.reachable` / `.full_stack` (scopes),
`.branch(method)`, `.finding(summary)`, `.source(context=3)`.

**`Function`** — `fqn`, `name`, `params`, `kind`, `parent_class`,
`parent_function`, `location`, `overloads`; `.body` / `.reachable`,
`.called_by` / `.calls`, `.decorators`, `.parameter_named(name)`.

**`InputRead`** — `source` (typed `InputSource`), `access_pattern`,
`cardinality`, `value_type`, `expression`, `function`, `location`, `.value`.

**`Effect`** — `category`, `function`, `location`, `expression`, `scope`, `key`;
`.target`, `.value`.

**`Condition`** — `expression`, `kind`, `operator`, `.true_branch` /
`.false_branch`, `.left` / `.right`, `.guard` (L2's guard classification, or
`None`). A `Predicate` is its value-producing sibling (no branches).

**`CallSite`** — `target` (a `Function` or `None`), `function`,
`target_expression`, `arguments`, `location`, `.return_value`.

---

## Running your own rules

The bundled rules are demos. Point the scanner at your own directory:

```bash
flawed scan TARGET --rules-dir /abs/path/to/myrules   # replaces the built-ins
```

The discovery model is deliberately simple:

- A module is a rule **iff** it carries an `@detector` — helper modules with no
  detector are never mistaken for rules.
- The rules directory is on `sys.path`, so rules import siblings and shared
  packages with ordinary imports (no `sys.path` shim).
- `_`-prefixed files and directories are **not** scanned for rules (but remain
  importable) — put shared helpers in a `_lib/` package.
- `--rules-dir` must be an absolute path. If a configured rules directory is
  missing or has no rule files, the loader **warns** — it never silently loads
  zero rules.

```
myrules/
  _lib/                      # importable helpers, never scanned
    predicates.py
  inputs_to_writes.py        # carries @detector → a rule
```

See [cli.md](cli.md) for the full scan workflow and output formats.

---

## Analysis gaps: the engine never fails open

When analysis is incomplete — an unparsable file, an unresolved symbol, a CFG
that could not be built — the engine records an `AnalysisGap` instead of
silently dropping the case. Gaps propagate automatically from extraction through
the model into findings: when a gap affects a finding it appears in
`Finding.gaps`. Rule authors never create or check for gaps explicitly. A
missing analysis is made explicit, not masked as a clean negative.

---

## Where next

- [analysis-model.md](analysis-model.md) — the model your rules query.
- [python-api.md](python-api.md) — using the same API interactively in a REPL or
  script.
- [cli.md](cli.md) — running scans, output formats, configuration.
- [provider-authoring.md](provider-authoring.md) — teaching the engine a new
  framework so your rules see its routes, inputs, and effects.
