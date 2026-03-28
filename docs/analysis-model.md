# The analysis model

`flawed` builds a framework-aware model of a Python web application and lets you
query it. This document describes what that model contains and how to think
about it. For the API that exposes it, see [writing-rules.md](writing-rules.md);
for interactive use, [python-api.md](python-api.md).

It describes how a request flows through code — where inputs enter, what guards
run, what state changes, where values travel.

---

## Three layers

The engine is built in three strict layers, each consuming only the one below:

| Layer | Responsibility |
|-------|----------------|
| **Code Index** (L1) | Language-level structural extraction: AST, control-flow graphs, call graph, value-flow edges, symbols and resolved types. Framework-agnostic. |
| **Semantic** (L2) | Framework interpretation. Pluggable *providers* turn raw structure into meaning — recognising routes, request reads, effects, and guards for a given framework. |
| **Rule API** (L3) | The vocabulary you write rules in: routes, inputs, effects, checks, value flow, findings. |

A rule author works entirely at Layer 3. Framework knowledge lives only in
Layer 2 providers (see [provider-authoring.md](provider-authoring.md)); the
layers below are an implementation detail you query through, not against.

---

## What the model contains

### Routes

Each HTTP endpoint the engine reconstructs is a `Route`: its `endpoint` name,
`url_rule`, accepted `methods`, the `handler` function, and its route `group`
(blueprint / router / app). Routes are reconstructed from framework registration
patterns — decorators, URL rules, blueprints, class-based views — by the active
providers.

### Request inputs

A read of attacker-supplied data is an `InputRead` with a **typed source**:
query string, form field, JSON body, header, cookie, path parameter, file
upload, raw body. Each read carries its access pattern, cardinality
(single/multi), an optional runtime type constraint, and a value handle for flow
tracing.

Server-side session data is **not** an input source — it is modelled as a state
effect (below), because session contents are not directly attacker-controlled.

### Effects

A modelled side effect is an `Effect` drawn from a fixed taxonomy: database
write/delete/read, file write/read, scoped-state write/read, configuration
write, outbound request, notification. State effects additionally carry a
**scope** describing persistence lifetime —

- **request** — dies when the request completes (e.g. request-local context),
- **session** — persists across one user's requests,
- **server** — persists across requests and is observable by *other* users —

and a **key** when the written/read name is determinable. Each effect exposes
what is written (`value`) and what is written to (`target`) as value handles.

### Checks

A `check` is a provider-recognised security-relevant guard on a route —
authentication, authorization, CSRF protection, schema validation, rate
limiting, and so on — labelled by category and by the provider that recognised
it. Checks are what let a rule ask "what protects this route?" without hard-coding
any framework's idioms.

### Conditions, predicates, and control flow

The model distinguishes a **condition** (a branch test — `if`/`elif`/`while`/
ternary that steers control flow, with `true_branch`/`false_branch` scopes and an
optional guard classification) from a **predicate** (a comparison/membership/
identity/truthiness expression produced as a *value*, e.g. a `return x is not
None`). Over any scope, a `ControlFlowView` answers ordering questions:
*dominance* (every path to B passes through A) and *precedence* (A runs before B
on all paths).

### The call graph and reachability

The engine resolves calls into a call graph, which is what makes analysis reach
beyond a single function. You query code through a **scope**, and the scope you
pick decides how far analysis travels:

| Scope | Reach |
|-------|-------|
| `route.body` / `fn.body` | the single function — intra-procedural |
| `route.reachable` / `fn.reachable` | the function plus everything it transitively calls — interprocedural, cross-file |
| `route.full_stack` | reachable code plus lifecycle hooks and middleware |

The same query (`reads`, `effects`, `checks`, …) returns more or less depending
on the scope it runs against.

### Value flow

Value flow answers one question: *does the value here reach that place?* It is a
**forward** reachability over value-flow edges — assignments, argument passing,
returns, attribute writes, and framework-aware propagation (a library call that
moves a value from an argument to its result, a proxy object that views session
state). Layer 1 produces intra-function edges; the Layer 2 tracer stitches them
across calls and files along the call graph.

Every flow query bottoms out in that forward reach:

- `a.flows_to(b)` — does value `a` reach `b`?
- `target.derived_from(Source())` — does *any* read of a given source category
  reach `target`?
- `scope.reads_flowing_to(target)` — which reads in this scope reach `target`?

Because reach follows the call graph, it is interprocedural only as far as the
scope allows and as far as calls resolve. An unresolved call is a dead end.

### Types and type disagreement

The Code Index resolves types via a type oracle. Where two independent type
engines infer *materially different* concrete types for the same expression, the
engine records a **type disagreement** (`kb.type_disagreements`) — a neutral
signal that a value's type is ambiguous, exposed for rules to interpret.

### Structural facts

Beyond the web model, the index exposes ordinary program structure: every
`Function` (signature, kind, decorators, callers/callees, `@overload` stubs) and
`Class` (bases, MRO, methods, inherited methods). Rules can navigate these
directly via `kb.functions` and `kb.classes`.

---

## Conservative by construction

Two principles shape how the model answers:

**Flow answers are conservative.** `flows_to` and `derived_from` return `True`
only when a flow is *proven*. When a flow cannot be proven they return `False` —
meaning "not proven", not "provably absent". They never return `True`
incorrectly. Backward derivation is the hardest query and the most likely to
under-report. Treat a negative as "unknown", not "safe".

**The engine never fails open.** When analysis is incomplete — a file that will
not parse, a symbol that will not resolve, a control-flow graph that cannot be
built — the engine records an `AnalysisGap` rather than silently producing a
clean negative. Gaps propagate automatically through the layers and surface on
the findings they affect. A missing analysis is always made explicit.

---

## Where next

- [writing-rules.md](writing-rules.md) — the API that queries this model.
- [python-api.md](python-api.md) — exploring the model interactively.
- [provider-authoring.md](provider-authoring.md) — extending the Semantic Layer
  to a new framework.
