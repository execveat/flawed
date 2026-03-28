# Python API

flawed's analysis is a Python library. The same objects a
detection rule receives are available interactively — open a repository, query
its model, and trace how values flow. This is the fastest way to understand a
codebase before writing a rule against it.

For authoring detection rules, see [Writing rules](writing-rules.md); for the
model those rules query, see [Analysis model](analysis-model.md).

## Opening a repository

```python
from flawed import open_repo

kb = open_repo("path/to/app")
```

`open_repo(path)` runs the pipeline and returns a `RepoView` — the single entry
point for navigation. Repeated calls on an unchanged tree reuse an in-process
cache, so iterative exploration does not re-pay the build.

If a substantial repository yields **zero routes**, `open_repo` emits a
`RoutelessRepoWarning` — usually the path points above the application package,
or no provider recognized the framework. The warning is deliberate: a missing
analysis is surfaced, never silently returned as an empty view.

## Navigating the model

`RepoView` exposes the top-level collections:

```python
kb.routes        # RouteCollection   — HTTP endpoints
kb.functions     # FunctionCollection
kb.classes       # ClassCollection
kb.gaps          # analysis gaps (where the engine lost confidence)
```

Collections behave like immutable sequences and compose with chainable filters:

```python
kb.routes[0]                                   # index → element
kb.routes[:5]                                   # slice → a new RouteCollection
kb.routes.where(lambda r: r.method == "POST")   # arbitrary predicate
kb.functions.named("login")                     # by name
kb.functions.decorated_with("login_required")   # by decorator
kb.classes.subclasses_of("Resource")            # by base class
kb.routes.count_by(lambda r: r.method)          # Counter({'GET': 35, 'POST': 58})
kb.routes.group_by(lambda r: r.method)          # dict[str, RouteCollection]
kb.routes.tabulate("method", "path")            # aligned columns to stdout
```

Every object and collection has a concise `__repr__`, so echoing one in a REPL
shows a one-line summary (e.g. `RouteCollection(75) [Route(GET / → index, …), …]`)
rather than a wall of nested data. Use `.detail()` for the full dump. `.one()`
and `.first()` collapse a collection to a single element (`.one()` raises unless
exactly one matches).

## Querying a route

Each route exposes scopes — slices of the call graph reachable from its handler:

```python
route = kb.routes.where(lambda r: r.path == "/users/<id>").one()

route.body         # the handler function itself
route.reachable    # everything called transitively from the handler
route.full_stack   # reachable + framework lifecycle (before/after hooks, guards)
```

On any scope you ask what happens inside it:

```python
from flawed.inputs import Query, Form, Json
from flawed.effects import Mutation, State, Response, Cache

scope = route.reachable

scope.reads(Form())                  # request inputs read (Form / Json / Query / …)
scope.effects(Mutation.write())      # state-changing operations
scope.checks(category="AUTHENTICATION")  # security checks (auth, CSRF, rate limit)
scope.calls(...)                     # call sites matching a function selector
scope.sinks(kind="SQL_INJECTION")    # taint sinks
scope.conditions()                   # branch guards along the scope
```

## Tracing value flow

Input reads and effects carry a `ValueHandle` you can follow through the call
graph — the basis of "does this input reach that operation":

```python
for read in route.reachable.reads(Query()):
    for effect in route.reachable.effects(State.write()):
        if read.value.flows_to(effect.target):
            print(read, "→", effect)
```

`ValueHandle` also offers `.flows_from(...)` and `.derived_from(...)` for the
reverse and for provenance across transforms. Pair flow with `scope.conditions()`
to see whether a guard sits between a source and a sink.

To read the underlying source for any route or function, call `.source()`.
