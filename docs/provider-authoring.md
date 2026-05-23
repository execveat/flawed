# Authoring a provider

A **provider** teaches the engine about one framework or library. flawed's core
analysis (Layer 1 structure, Layer 2 model) is framework-agnostic; all framework
knowledge — what counts as a route, an input, an auth check, a state write — lives
in providers. Write one to make the engine understand a framework it doesn't ship
support for, and every rule (and the [Python API](python-api.md)) sees the routes,
inputs, effects, and checks your provider declares.

A provider is **declarative**: you subclass `Provider` and list patterns keyed by
fully-qualified name (FQN). You do not write analysis code — you describe which
library symbols mean what, and the engine matches them against the call graph.

## A minimal provider

`src/flawed/_semantic/providers/flask_login.py` is the canonical small example.
Its shape:

```python
from typing import ClassVar

from flawed._semantic.providers._base import (
    CheckKind, EffectCallPattern, HookType, LifecycleRegistrationPattern,
    Provider, ProviderMeta, SecurityCheckPattern, StateProxyPattern,
)


class FlaskLoginProvider(Provider):
    meta = ProviderMeta(
        id="flask-login",
        name="Flask-Login",
        version="0.1.0",
        library="Flask-Login",
        library_fqn="flask_login",      # activates only when this import is present
    )

    # Public API re-exported from submodules → canonical FQN.
    fqn_aliases: ClassVar[dict[str, str]] = {
        "flask_login.utils": "flask_login",
        "flask_login.login_manager": "flask_login",
    }

    checks = (
        SecurityCheckPattern(
            fqn="flask_login.login_required",
            kind=CheckKind.DECORATOR,
            category="AUTHENTICATION",
            description="Requires an authenticated user",
        ),
    )

    effects = (
        EffectCallPattern(
            fqn="flask_login.login_user",
            category="STATE_WRITE",
            scope="SESSION",
            keys=("_user_id", "_fresh"),
            description="Writes auth state to the session",
        ),
    )

    proxies = (
        StateProxyPattern(
            fqn="flask_login.current_user",
            resolves_to="flask.g._login_user",
            scope="REQUEST",
            description="LocalProxy loaded from the session",
        ),
    )

    lifecycle = (
        LifecycleRegistrationPattern(
            registration_fqn="flask_login.LoginManager.init_app",
            hook_type=HookType.AFTER_HANDLER,
            description="Installs a per-response hook",
        ),
    )
```

`meta.library_fqn` gates activation: the provider only runs when the target
imports that library, so providers cost nothing on repos that don't use them.

## What a provider can declare

Each category is a class-attribute tuple of pattern objects. The common ones:

| Attribute | Pattern type(s) | Declares |
|-----------|-----------------|----------|
| `checks` | `SecurityCheckPattern`, `ClassAttributeGuardPattern` | auth / CSRF / rate-limit guards (decorators, calls, attributes) |
| `effects` | `EffectCallPattern`, `EffectAttributePattern`, `EffectSubscriptPattern` | state writes, config writes, responses, cache ops |
| `proxies` | `StateProxyPattern` | request-scoped proxies and what they resolve to |
| `lifecycle` | `LifecycleRegistrationPattern`, `LifecycleDecoratorPattern` | before/after-request hooks and how they register |
| `dispatches` | `DispatchPattern` | callbacks invoked by the framework per request |
| `routes` | `RouteCallPattern`, `ClassViewPattern`, `ImperativeRoutePattern`, `RouterGroupPattern` | how the framework declares endpoints and groups them |
| `inputs` | `InputAttributePattern`, `InputMethodPattern`, `InputContainerPattern`, `InputParameterPattern` | how handler code reads request data |
| `sinks` | `TaintSinkPattern` | dangerous operations (injection, traversal, …) |
| `safe_urls` / `validated_values` / `flow_propagators` | `SafeGeneratedURLPattern`, `ValidatedValueGuardPattern`, `FlowPropagatorPattern` | precision aids: provably-safe URLs, validation guards, value propagation across library calls |

`_base.py` is the full DSL reference — every pattern type, its fields, and the
`ArgRef` / `TypeCheckPredicate` helpers for argument- and type-conditioned
matching. Model a new provider on an existing one of the same framework shape
(a routing framework, an auth library, a crypto library) rather than from
scratch.

## Registering and verifying

Built-in providers are discovered automatically: any `Provider` subclass in a
non-underscore module under `src/flawed/_semantic/providers/` is picked up and
ordered by `meta.id` — no registry edit needed. Drop your module in, and it
activates whenever its `library_fqn` is imported by the target.

Verify it without writing a rule:

```bash
flawed providers list                 # confirm your provider is discovered
flawed providers show flask-login     # per-category pattern breakdown
flawed providers coverage TARGET      # did it activate on a real repo? what matched?
flawed scan TARGET --provider flask-login   # force-enable while testing
```

Provider enable/disable and per-provider settings are configurable under the
`providers` key (see `flawed config show`); `--provider` / `--no-provider`
override activation for a single scan.

## Principles

- **One source of truth per concept.** A symbol's meaning is declared once, by
  FQN, in the provider — never re-encoded in a rule.
- **No fail-open.** When matching can't resolve something, the engine records an
  analysis gap; a provider should not guess. Prefer an honest gap to a wrong
  match.
- **Activation is import-gated.** Keep `library_fqn` precise so the provider stays
  inert on repos that don't use the library.

Once your provider lands, the model it produces is queryable exactly like any
built-in framework's — write detectors against it per [Writing rules](writing-rules.md).
