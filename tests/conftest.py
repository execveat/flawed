"""Root test conftest — timing guard + session-scoped fixture app analysis.

Timing guard
~~~~~~~~~~~~
Every individual test has a wall-clock budget (default: 5 s).  Tests that
exceed the budget FAIL with a message pointing the author to session-scoped
fixtures.  This prevents agents and humans from accidentally calling
``open_repo()`` inline in each test method — the pipeline takes ~2 s per
invocation, so even a single inline call pushes a test close to the limit
and two calls blow past it.

Exempt a legitimately slow test with ``@pytest.mark.slow``.

Session-scoped analysis fixtures
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
The L1+L2 pipeline takes ~2s per app. Every fixture app is a static directory
and every RepoView is immutable (frozen dataclasses). Session-scoping means
the pipeline runs ONCE per app per test session, not once per test.

To add a new fixture app:
1. Create the app directory under tests/fixtures/apps/
2. Add a session-scoped fixture HERE (not in a sub-conftest)
3. Tests receive the fixture by name — never call open_repo() directly

IMPORTANT: Do not call ``open_repo()`` or ``build_index()`` directly in test
functions or test classes. Always receive the analyzed result as a pytest
fixture parameter. Direct calls bypass session caching and multiply the
suite runtime by the number of tests.
"""

from __future__ import annotations

import contextlib
import time
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from tests._guards import subprocess_guard
from tests.helpers.artifact_fixtures import load_fixture, load_index
from tests.testmon_fixture_dep import fixtures_changed, write_stamp

if TYPE_CHECKING:
    from flawed._semantic._provider_engine import ProviderEngineResult
    from flawed.repo import RepoView


_GIT_OVERRIDE_VARS = ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_CEILING_DIRECTORIES")


@pytest.fixture(autouse=True)
def _isolate_process_state(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Restore process-level state that CLI tests may change.

    Three sources of cross-test pollution (DISC-030):

    1. **Git env vars**: When tests run inside a pre-commit hook,
       ``GIT_DIR``/``GIT_WORK_TREE`` are inherited.  ``subprocess``
       calls to ``git`` then ignore ``cwd`` / ``-C`` and operate on
       the parent repository, corrupting its config.

    2. **Working directory**: CLI scan commands call ``os.chdir()``
       via ``entered_target()``.  That context manager restores cwd on
       exit, but this fixture is the backstop. If the cwd isn't restored, subsequent
       tests that resolve relative paths (rule modules, fixture apps)
       find the wrong files or fail on deleted temp dirs.

    3. **Persistent caches in the real user data dir**: ``load_config``
       resolves ``data_dir``/``state_dir`` from ``$XDG_DATA_HOME`` /
       ``$XDG_STATE_HOME`` (``flawed_data_dir()``).  Left unset, a CLI
       scan in a test would write the L1 artifact cache *and* the
       per-detector results cache (FLAW-137) into the developer's real
       ``~/.local/share/flawed`` — leaking garbage and, worse, risking
       a stale cross-test cache hit.  Anchoring both to a per-test tmp
       dir keeps every test's cache hermetic.

    ``monkeypatch.chdir()`` records the original cwd and restores it
    on teardown, preventing the first two issues.
    """
    for key in _GIT_OVERRIDE_VARS:
        monkeypatch.delenv(key, raising=False)
    # Anchor cwd — monkeypatch restores it even if a CLI test moves it.
    monkeypatch.chdir(Path(__file__).parent.parent)
    # Anchor flawed's XDG dirs to a per-test tmp so caches never touch the
    # real user data dir and never leak across tests.
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg-data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "xdg-state"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg-config"))


# ---------------------------------------------------------------------------
# Timing guard — fail tests that exceed the per-test wall-clock budget
# ---------------------------------------------------------------------------

#: Warn (via extra section in output) when a single test exceeds this.
#: This is the real signal for "is this test creeping toward an inline
#: analysis call" — kept tight so slow tests surface in output.
WARN_SECONDS: float = 5.0

#: Hard-fail a test when it exceeds this.  The guard exists to catch an
#: *accidental* inline ``open_repo()``/``build_index()`` in a test body —
#: which costs L1 + semantic build (tens of seconds on any real fixture),
#: not the ~2 s of the stale comment this replaced.  A hard limit near the
#: warn threshold (the old 5 s) false-fails legitimately-heavy-but-bounded
#: tests under suite/CI load contention (see FLAW-162) without catching
#: anything the warn threshold doesn't already flag.  10 s sits well below
#: any genuine inline-analysis cost while absorbing wall-clock jitter.
FAIL_SECONDS: float = 10.0

_start_key = pytest.StashKey[float]()


def pytest_runtest_call(item: pytest.Item) -> None:
    """Record wall-clock start time after fixture setup, before test body."""
    item.stash[_start_key] = time.monotonic()


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo[None]):
    """Check wall-clock duration after the call phase and fail slow tests."""
    outcome = yield
    report = outcome.get_result()

    if report.when != "call":
        return

    start = item.stash.get(_start_key, None)
    if start is None:
        return

    elapsed = time.monotonic() - start

    # @pytest.mark.slow exempts from timing guard
    if item.get_closest_marker("slow") is not None:
        return

    if elapsed >= FAIL_SECONDS:
        report.outcome = "failed"
        report.longrepr = (
            f"TIMING GUARD: test took {elapsed:.1f}s (limit: {FAIL_SECONDS:.0f}s).\n"
            f"\n"
            f"Individual tests must not call open_repo() or build_index() directly.\n"
            f"Use a session-scoped fixture from tests/conftest.py instead:\n"
            f"\n"
            f"    def test_something(self, flask_basic):\n"
            f"        routes = flask_basic.routes  # shared, no re-analysis\n"
            f"\n"
            f"If this test is legitimately slow, mark it with @pytest.mark.slow\n"
        )
    elif elapsed >= WARN_SECONDS:
        report.sections.append(
            (
                "timing warning",
                f"Test took {elapsed:.1f}s (warn threshold: {WARN_SECONDS:.0f}s). "
                f"Consider using a session-scoped fixture.",
            )
        )


# ---------------------------------------------------------------------------
# testmon fixture-dependency bridge (FLAW-197)
# ---------------------------------------------------------------------------
#
# testmon selects tests from coverage of *executed* Python. Fixture apps are
# ingested as data (ast.parse'd, never executed), so coverage — and therefore
# testmon — never sees them as a dependency of the specs that open_repo() them.
# Editing only a fixture would silently deselect the very specs it changes.
# testmon offers no hook to register a data-file dependency, so instead we detect
# a fixtures-tree change and force ONE full (non-selective) run; testmon still
# collects data, so later runs stay incremental. See tests/testmon_fixture_dep.py.

#: Attribute on ``config`` carrying ``(stamp_path, hash)`` to persist on success.
_FIXTURES_STAMP_PENDING = "_flaw197_fixtures_stamp_pending"


@pytest.hookimpl(tryfirst=True)
def pytest_configure(config: pytest.Config) -> None:
    """Deactivate testmon *selection* for this run when fixture apps changed.

    Runs ``tryfirst`` so ``config.option.testmon_noselect`` is set before
    testmon's own ``pytest_configure`` reads it. No-op unless testmon selection
    is active and this is a non-xdist-worker process.
    """
    # Enforcement: the subprocess guardrail is ALWAYS active (no env flag), so it
    # installs/registers BEFORE testmon's early-return below.
    subprocess_guard.install()
    config.pluginmanager.register(subprocess_guard, "flawed-subprocess-guard")
    if not getattr(config.option, "testmon", False):
        return
    if getattr(config.option, "testmon_noselect", False):
        return
    if hasattr(config, "workerinput"):  # xdist worker — the controller decides
        return
    stamp_path = Path(config.rootpath) / ".testmondata.fixtures-stamp"
    changed, current = fixtures_changed(FIXTURES, stamp_path)
    if changed:
        config.option.testmon_noselect = True
        setattr(config, _FIXTURES_STAMP_PENDING, (stamp_path, current))


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    """Persist the fixtures stamp only after a fully green forced run.

    A failed forced run leaves the old stamp untouched, so the next run forces a
    full pass again — fail toward re-running fixture-affected specs, never toward
    silently skipping them.
    """
    pending = getattr(session.config, _FIXTURES_STAMP_PENDING, None)
    if pending is None or exitstatus != 0:
        return
    stamp_path, current = pending
    # The stamp is an optimization; an unwritable stamp just re-forces next run.
    with contextlib.suppress(OSError):
        write_stamp(stamp_path, current)


# ---------------------------------------------------------------------------
# Fixture app root directories
# ---------------------------------------------------------------------------

FIXTURES = Path(__file__).parent / "fixtures" / "apps"
SEMANTIC_FIXTURES = FIXTURES / "semantic"

# ---------------------------------------------------------------------------
# Basics fixture apps (L1 structural extraction)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def functions_app() -> RepoView:
    """Analyze the functions/ fixture (top-level, nested, lambdas, methods)."""
    return load_fixture("functions")


@pytest.fixture(scope="session")
def classes_app() -> RepoView:
    """Analyze the classes/ fixture (inheritance, MRO, abstract)."""
    return load_fixture("classes")


@pytest.fixture(scope="session")
def decorators_app() -> RepoView:
    """Analyze the decorators/ fixture (simple, stacked, parameterized)."""
    return load_fixture("decorators")


@pytest.fixture(scope="session")
def imports_app() -> RepoView:
    """Analyze the imports/ fixture (cross-file calls, aliased imports)."""
    return load_fixture("imports")


@pytest.fixture(scope="session")
def flask_basic_l1() -> RepoView:
    """Analyze the flask_basic/ fixture (non-semantic: routes+calls+flow)."""
    return load_fixture("flask_basic")


@pytest.fixture(scope="session")
def overload_signatures() -> RepoView:
    """Analyze the overload_signatures/ fixture (FLAW-265).

    ``load_account`` carries two ``@overload`` stubs (``Literal[True]`` /
    ``Literal[False]`` selector) plus the ``bool`` implementation, so the typed
    ``Function`` surface can expose the per-stub signatures.
    """
    return load_fixture("overload_signatures")


# ---------------------------------------------------------------------------
# Semantic fixture apps (L1 + L2: framework-specific interpretation)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def flask_basic() -> RepoView:
    """Analyze the semantic/flask_basic fixture (routes, inputs, effects)."""
    return load_fixture("semantic/flask_basic")


@pytest.fixture(scope="session")
def flask_sqlalchemy_orm_reads() -> RepoView:
    """Analyze the semantic/flask_sqlalchemy_orm_reads fixture (FLAW-116).

    The canonical flask-sqlalchemy / SQLAlchemy read idioms
    (``Model.query.…first()``, ``db.session.query(…).first()``,
    ``db.session.get(…)``, ``Model.query.get(…)``) each resolve to their
    library ``Query``/``Session`` FQN so the SQLAlchemy provider produces a
    modeled ``Db.read()`` effect — replacing the source-string idiom fallback
    for real declarative models. The fixture imports only ``flask_sqlalchemy``
    (never ``sqlalchemy`` directly), so it also covers FLAW-190 activation.
    """
    return load_fixture("semantic/flask_sqlalchemy_orm_reads")


@pytest.fixture(scope="session")
def orm_query_split() -> RepoView:
    """Analyze the semantic/orm_query_split fixture (FLAW-275).

    Exercises the split-statement ORM idiom ``q = Model.query`` then
    ``q.filter_by(...).first()`` (idiomatic in real apps), which previously
    resolved the chain off the local variable to a namespace-local pseudo-FQN —
    losing the ``Db.read()`` effect the single-expression form already produces.
    Includes a non-model ``q = <plain>.query`` negative route that must NOT
    canonicalize, so the recovery stays gated to provable declarative models.
    """
    return load_fixture("semantic/orm_query_split")


@pytest.fixture(scope="session")
def flask_correlation_fp() -> RepoView:
    """Analyze the semantic/flask_correlation_fp fixture (FLAW-126).

    Same-logical-input correlation regressions: a ``?token=`` query guard and an
    unrelated ``<token>`` path parameter (a name-collision false-positive), and two
    different request values through two transforms (an unrelated-transform-pair false-positive).
    """
    return load_fixture("semantic/flask_correlation_fp")


@pytest.fixture(scope="session")
def oauth_claim_inputs() -> RepoView:
    """Analyze the semantic/oauth_claim_inputs fixture (FLAW-202).

    An authlib callback navigates the token-exchange result into the ``userinfo``
    claims container and reads the ``email``/``sub`` claims; the engine surfaces
    those keyed accesses as ``ProviderClaim`` input reads so a normalized gate
    derivation and the raw identity derivation of the same claim correlate via
    ``shares_origin``.
    """
    return load_fixture("semantic/oauth_claim_inputs")


@pytest.fixture(scope="session")
def oauth_claim_interproc() -> RepoView:
    """Analyze the semantic/oauth_claim_interproc fixture (FLAW-203).

    The authlib callback passes the ``userinfo`` claims container into a helper
    that reads ``email``/``sub`` off its parameter; the claim source must
    propagate across the call boundary so the helper's keyed reads surface as
    ``ProviderClaim`` input reads and a normalized gate derivation and the raw
    identity derivation of the same claim correlate via ``shares_origin``.
    """
    return load_fixture("semantic/oauth_claim_interproc")


@pytest.fixture(scope="session")
def oauth_factory_effects() -> RepoView:
    """Analyze the semantic/oauth_factory_effects fixture (FLAW-204).

    The OAuth client is reached via a registry attribute
    (``oauth.<provider>.authorize_access_token()``) whose type the index cannot
    resolve, so the client-method effects (OUTBOUND_REQUEST) are recognised by
    federation-specific bare method name — the same escape hatch the claims
    container uses.
    """
    return load_fixture("semantic/oauth_factory_effects")


@pytest.fixture(scope="session")
def flask_restx_api() -> RepoView:
    """Analyze the semantic/flask_restx_api fixture (flask-restx root-reexport idiom).

    The app imports ``Api``/``Namespace``/``Resource`` from the *package root*
    (``from flask_restx import ...``) — the dominant real-world idiom (a large API surface
    spread across submodules) — even though those classes are defined in
    submodules. The provider must declare the root-reexport FQN aliases or the
    ``@ns.route`` decorator and the ``Resource`` base both fail to match and the
    whole API is invisible (a corpus-wide false negative).
    """
    return load_fixture("semantic/flask_restx_api")


@pytest.fixture(scope="session")
def flask_intra_provenance() -> RepoView:
    """Analyze the semantic/flask_intra_provenance fixture (FLAW-172).

    A request value read into a local keeps its origin through an intra-function
    transform (``email.lower()``): ``derived_from`` / ``shares_origin`` resolve
    on the transformed local, while the transform is correctly *not*
    whole-value-preserving (a pure alias is).
    """
    return load_fixture("semantic/flask_intra_provenance")


@pytest.fixture(scope="session")
def flask_custom_guard_decorator() -> RepoView:
    """Analyze the semantic/flask_custom_guard_decorator fixture (FLAW-273a).

    Custom auth-guard decorators imported cross-module (the ``admins_only``
    / ``authed_only`` decorator shape).  ``@admins_only`` enforces BOTH authorization
    (``abort(403)``) and authentication (login redirect); the call-graph
    inference must expose both categories through ``scope.checks()`` so a
    coverage rule needing the previously-dropped category stops false-flagging
    the guarded route.
    """
    return load_fixture("semantic/flask_custom_guard_decorator")


@pytest.fixture(scope="session")
def flask_library_guard_decorators() -> RepoView:
    """Analyze the semantic/flask_library_guard_decorators fixture (FLAW-273b).

    LIBRARY auth-guard decorators on module-global instances -- flask-allows
    ``@allows.requires`` (``Allows()``) and Flask-HTTPAuth
    ``@basic_auth.login_required`` / ``@token_auth.login_required``
    (``HTTPBasicAuth()`` / ``HTTPTokenAuth()``).  Their wrapper bodies live in
    the third-party library, so recognition comes from the provider
    ``SecurityCheckPattern`` matched through the decorator's receiver type, not
    the call-graph auth-inference pass.  Includes a genuinely unguarded route
    and an unproven look-alike (a project ``login_required`` on a non-HTTPAuth
    object) that must NOT be recognized (false-negative guard).
    """
    return load_fixture("semantic/flask_library_guard_decorators")


@pytest.fixture(scope="session")
def flask_csrf_lifecycle() -> RepoView:
    """Analyze the semantic/flask_csrf_lifecycle fixture.

    Control-plane state via a ``before_request`` hook that gates
    ``csrf.exempt(view_func)`` on a presence-only token helper, plus a static
    ``@csrf.exempt`` decorator.  Exercises lifecycle dedup + presence gating of
    CSRF exemptions (FLAW-111).
    """
    return load_fixture("semantic/flask_csrf_lifecycle")


@pytest.fixture(scope="session")
def flask_upload_validation() -> RepoView:
    """Analyze the semantic/flask_upload_validation fixture (FLAW-105).

    Upload handlers validating different *subsets* of the dimensions an upload
    should check (filename / extension / size / content).  Exercises the upload-validation rule's
    dimension-aware classification: full validation is silent, partial
    validation yields a LOW dimension-specific finding, and a wholly
    unvalidated upload yields the MEDIUM finding.
    """
    return load_fixture("semantic/flask_upload_validation")


@pytest.fixture(scope="session")
def flask_self_service_writes() -> RepoView:
    """Analyze the semantic/flask_self_service_writes fixture (FLAW-168).

    User-scoped self-service writes (``ApiToken(user_id=current_user.id)``,
    ``filter_by(user_id=current_user.id)``) need only AUTHENTICATION —
    authorization-coverage analysis must not demand AUTHORIZATION for them —
    while writes with no principal-ownership binding (IDOR, global-config)
    remain distinguishable.
    """
    return load_fixture("semantic/flask_self_service_writes")


@pytest.fixture(scope="session")
def flask_csrf_app_global() -> RepoView:
    """Analyze the semantic/flask_csrf_app_global fixture (FLAW-128).

    Application-level CSRF registered via the ``CSRFProtect(app)`` constructor
    (not ``csrf.init_app(app)``).  Every state-changing route is globally
    protected, so the dedicated CSRF rule must not false-positive on them.
    """
    return load_fixture("semantic/flask_csrf_app_global")


@pytest.fixture(scope="session")
def flask_csrf_bare_unbound() -> RepoView:
    """Analyze the semantic/flask_csrf_bare_unbound fixture (FLAW-128 guard).

    A bare ``CSRFProtect()`` with no app argument and no ``init_app`` protects
    nothing.  The engine must NOT treat it as global CSRF coverage, so the
    mutating route stays flagged (fail-open guard).
    """
    return load_fixture("semantic/flask_csrf_bare_unbound")


@pytest.fixture(scope="session")
def flask_csrf_app_exempt() -> RepoView:
    """Analyze the semantic/flask_csrf_app_exempt fixture (FLAW-173).

    A global ``CSRFProtect(app)`` covers every route, but one route is declared
    ``@csrf.exempt`` and is therefore removed from the global guard.  the CSRF-exemption rule must
    subtract the decorator-form exemption and flag the exempted state-changing
    route while leaving the genuinely-covered route alone.
    """
    return load_fixture("semantic/flask_csrf_app_exempt")


@pytest.fixture(scope="session")
def flask_csrf_call_exempt() -> RepoView:
    """Analyze the semantic/flask_csrf_call_exempt fixture (FLAW-181).

    A global ``CSRFProtect(app)`` covers every route; the module-level CALL form
    ``csrf.exempt(view)`` / ``csrf.exempt(blueprint)`` (no enclosing function)
    must re-attribute a ``CONFIG_WRITE`` exemption onto the named view's route
    and every route under the named blueprint, so effect-based CSRF consumers
    recognise the exemption on ``full_stack``.
    """
    return load_fixture("semantic/flask_csrf_call_exempt")


@pytest.fixture(scope="session")
def flask_basic_provider_result() -> ProviderEngineResult:
    """Run provider matching for semantic/flask_basic provider inspection specs."""
    from flawed._semantic._provider_engine import ProviderEngine

    idx = load_index("semantic/flask_basic")
    return ProviderEngine().run(idx)


@pytest.fixture(scope="session")
def flask_add_url_rule() -> RepoView:
    """Analyze the semantic/flask_add_url_rule fixture."""
    return load_fixture("semantic/flask_add_url_rule")


@pytest.fixture(scope="session")
def flask_aliased() -> RepoView:
    """Analyze the semantic/flask_aliased fixture."""
    return load_fixture("semantic/flask_aliased")


@pytest.fixture(scope="session")
def flask_blueprints() -> RepoView:
    """Analyze the semantic/flask_blueprints fixture."""
    return load_fixture("semantic/flask_blueprints")


@pytest.fixture(scope="session")
def flask_package_blueprint() -> RepoView:
    """Analyze the semantic/flask_package_blueprint fixture."""
    return load_fixture("semantic/flask_package_blueprint")


@pytest.fixture(scope="session")
def flask_factory_blueprint() -> RepoView:
    """Analyze the semantic/flask_factory_blueprint fixture (FLAW-164).

    Factory-style: the Blueprint is constructed *inside* a factory function
    (``load_blueprints(app)``), not at module level.
    """
    return load_fixture("semantic/flask_factory_blueprint")


@pytest.fixture(scope="session")
def flask_call_route_group() -> RepoView:
    """Analyze the semantic/flask_call_route_group fixture (FLAW-166).

    Plain-function ``bp.add_url_rule`` route on a module-level blueprint, used
    to assert the ``_convert_call_route`` path attributes routes to their group.
    """
    return load_fixture("semantic/flask_call_route_group")


@pytest.fixture(scope="session")
def flask_factory_local_blueprint() -> RepoView:
    """Analyze the semantic/flask_factory_local_blueprint fixture (FLAW-169).

    Plain-function ``bp.add_url_rule`` route where ``bp`` is a Blueprint
    constructed *inside* a factory function (function-local binding).  The
    receiver must resolve to ``flask.Blueprint`` via its local constructor
    assignment, exactly as a module-level binding resolves via alias.
    """
    return load_fixture("semantic/flask_factory_local_blueprint")


@pytest.fixture(scope="session")
def flask_nested_blueprint() -> RepoView:
    """Analyze the semantic/flask_nested_blueprint fixture (FLAW-114)."""
    return load_fixture("semantic/flask_nested_blueprint")


@pytest.fixture(scope="session")
def flask_indirect() -> RepoView:
    """Analyze the semantic/flask_indirect fixture."""
    return load_fixture("semantic/flask_indirect")


@pytest.fixture(scope="session")
def flask_subclassed() -> RepoView:
    """Analyze the semantic/flask_subclassed fixture."""
    return load_fixture("semantic/flask_subclassed")


@pytest.fixture(scope="session")
def flask_class_view_factory() -> RepoView:
    """Analyze the semantic/flask_class_view_factory fixture."""
    return load_fixture("semantic/flask_class_view_factory")


@pytest.fixture(scope="session")
def fastapi_basic() -> RepoView:
    """Analyze the semantic/fastapi_basic fixture."""
    return load_fixture("semantic/fastapi_basic")


@pytest.fixture(scope="session")
def django_basic() -> RepoView:
    """Analyze the semantic/django_basic fixture."""
    return load_fixture("semantic/django_basic")


@pytest.fixture(scope="session")
def drf_basic() -> RepoView:
    """Analyze the semantic/drf_basic fixture."""
    return load_fixture("semantic/drf_basic")


@pytest.fixture(scope="session")
def flask_init_app() -> RepoView:
    """Analyze the semantic/flask_init_app fixture."""
    return load_fixture("semantic/flask_init_app")


@pytest.fixture(scope="session")
def sqlalchemy_basic() -> RepoView:
    """Analyze the semantic/sqlalchemy_basic fixture."""
    return load_fixture("semantic/sqlalchemy_basic")


@pytest.fixture(scope="session")
def flask_real_world_gaps() -> RepoView:
    """Analyze the semantic/flask_real_world_gaps fixture.

    Exercises real-world Flask patterns that exposed engine gaps:
    MethodView class-level decorators, global CSRFProtect, blueprint-level
    rate limiting, redirect target classification.
    """
    return load_fixture("semantic/flask_real_world_gaps")


# ---------------------------------------------------------------------------
# Detection fixture apps (single-file end-to-end fixtures)
# ---------------------------------------------------------------------------
# Single-file fixtures (one app per ``detection/<name>.py``) loaded from
# committed artifacts via the ``_SINGLE_FILE_CONTAINER_DIRS`` mechanism; the
# loader resolves a file's repo_root to its parent (matching build_index).


@pytest.fixture(scope="session")
def detection_credential_derivation_divergence() -> RepoView:
    """Analyze the detection/credential_derivation_divergence fixture.

    Multi-construct interprocedural fixture (a credential read split from its
    presence predicate across a call boundary, plus lifecycle hooks). Consumed
    by branch-reconstruction coverage in
    ``tests/specs/semantic/test_branch_reconstruction.py``.
    """
    return load_fixture("detection/credential_derivation_divergence.py")


@pytest.fixture(scope="session")
def flask_sibling_apps() -> RepoView:
    """Analyze sibling Flask packages with colliding blueprint names."""
    return load_fixture("semantic/flask_sibling_apps")
