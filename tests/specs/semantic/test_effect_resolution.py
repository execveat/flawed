"""EP-3/EP-5: Effect resolution tests.

Tests that the Semantic API correctly detects effects declared by
providers, across all complexity levels and pattern types.

Pattern types under test:
  - EffectCallPattern (db.session.commit(), redirect(), etc.)
  - EffectAttributePattern (g.user = value)
  - EffectSubscriptPattern (session["key"] = value)
  - When-predicate discrimination (session.execute(Insert) vs Select)
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from flawed.effects import Config, Db, Effect, EffectCategory, Response, State, StateScope

if TYPE_CHECKING:
    from flawed.repo import RepoView
    from flawed.route import Route


_EFFECT_CALL_FQN_GAP = (
    "P3.3-GAP-01 [blocked-on: L1-H04/L1-H05]: method effects on inferred "
    "object types require type enrichment to canonicalize local variable FQNs "
    "back to provider-declared base FQNs."
)
_SUBCLASS_EFFECT_GAP = (
    "P3.3-GAP-02 [blocked-on: L1-H04/L1-H05]: inherited method calls require "
    "MRO/type enrichment to canonicalize subclass FQNs to provider-declared "
    "base model effect FQNs."
)
_DJANGO_EFFECT_GAP = (
    "P3.3-GAP-02 [blocked-on: L1-H04/L1-H05]: Django model method calls "
    "(user.save(), User.objects.all()) require type enrichment to match "
    "provider-declared effect FQNs."
)
_WHEN_PREDICATE_GAP = (
    "P3.3-GAP-04 [blocked-on: L1-H04/L1-H05]: when-predicate type_is/type_in "
    "discrimination requires L1 type enrichment to evaluate argument types."
)
pytestmark = pytest.mark.slow


def _route(repo: RepoView, endpoint: str) -> Route:
    matches = tuple(route for route in repo.routes if route.endpoint == endpoint)
    assert matches, f"route endpoint {endpoint!r} was not discovered"
    assert len(matches) == 1, f"expected one route for endpoint {endpoint!r}, got {len(matches)}"
    return matches[0]


def _route_by_handler(repo: RepoView, handler_suffix: str) -> Route:
    matches = tuple(route for route in repo.routes if route.handler.fqn.endswith(handler_suffix))
    assert matches, f"route handler ending with {handler_suffix!r} was not discovered"
    assert len(matches) == 1, (
        f"expected one route for handler {handler_suffix!r}, got {len(matches)}"
    )
    return matches[0]


def _all_effects(repo: RepoView) -> tuple[Effect, ...]:
    return tuple(effect for route in repo.routes for effect in route.body.effects())


def _assert_repo_effect(repo: RepoView, category: EffectCategory) -> Effect:
    for effect in _all_effects(repo):
        if effect.category is category:
            _assert_location(effect)
            return effect
    categories = sorted({effect.category.name for effect in _all_effects(repo)})
    raise AssertionError(f"expected {category.name} in repo effects; saw {categories}")


def _assert_effect(
    route: Route,
    category: EffectCategory,
    *,
    scope: StateScope | None = None,
    key: str | None = None,
    expression: str | None = None,
    expression_contains: str | None = None,
    function_contains: str | None = None,
) -> Effect:
    for effect in route.body.effects():
        if effect.category is not category:
            continue
        if scope is not None and effect.scope is not scope:
            continue
        if key is not None and effect.key != key:
            continue
        if expression is not None and effect.expression != expression:
            continue
        if expression_contains is not None and expression_contains not in effect.expression:
            continue
        if function_contains is not None and function_contains not in effect.function.fqn:
            continue
        _assert_location(effect)
        return effect

    observed = [
        (
            effect.category.name,
            effect.scope.name if effect.scope else None,
            effect.key,
            effect.expression,
        )
        for effect in route.body.effects()
    ]
    raise AssertionError(f"expected {category.name} effect on {route.endpoint}; saw {observed}")


def _assert_location(effect: Effect) -> None:
    assert effect.location.file
    assert effect.location.line > 0


# =====================================================================
# EffectCallPattern
# =====================================================================


class TestEffectCallPattern:
    """Test detection of function-call effects.

    Provider declaration:
        EffectCallPattern(
            fqn="sqlalchemy.orm.Session.commit",
            category="DB_WRITE",
        )
    """

    # -- L0: Direct usage ------------------------------------------------

    def test_l0_db_commit(self, flask_basic: RepoView) -> None:
        """db_session.commit() → DB_WRITE effect.

        Fixture: flask_basic/app.py::effect_db_write()
        EXPECT: one DB_WRITE effect in route "/effects/db_write"
        """
        route = _route(flask_basic, "effect_db_write")

        effect = route.body.effects(Db.write()).one()

        assert effect.category is EffectCategory.DB_WRITE
        assert "commit" in effect.expression
        _assert_location(effect)

    def test_l0_redirect(self, flask_basic: RepoView) -> None:
        """redirect() → RESPONSE_WRITE effect.

        Fixture: flask_basic/app.py::effect_response_write()
        EXPECT: one RESPONSE_WRITE effect
        """
        route = _route(flask_basic, "effect_response_write")

        effect = route.body.effects(Response.write()).one()

        assert effect.category is EffectCategory.RESPONSE_WRITE
        assert effect.expression == 'redirect(url_for("index"))'
        _assert_location(effect)

    def test_l0_set_cookie(self, flask_basic: RepoView) -> None:
        """response.set_cookie() → RESPONSE_WRITE effect.

        Type enrichment resolves the local ``resp`` to ``Response``, so the
        method-call effect canonicalizes (formerly P3.3-GAP-01).

        Fixture: flask_basic/app.py::effect_response_cookie()
        """
        route = _route(flask_basic, "effect_response_cookie")

        effect = _assert_effect(
            route,
            EffectCategory.RESPONSE_WRITE,
            expression_contains="set_cookie",
        )

        assert effect.expression == 'resp.set_cookie("token", "abc123")'

    def test_l0_flash(self, flask_basic: RepoView) -> None:
        """flash() → RESPONSE_WRITE effect.

        Fixture: flask_basic/app.py::effect_flash()
        """
        route = _route(flask_basic, "effect_flash")

        effect = _assert_effect(route, EffectCategory.RESPONSE_WRITE, expression_contains="flash")

        assert effect.expression == 'flash("Message sent!")'

    def test_l0_login_user(self, flask_basic: RepoView) -> None:
        """login_user() → STATE_WRITE effect (SESSION scope).

        Fixture: flask_basic/app.py::do_login()
        EXPECT: STATE_WRITE with scope=SESSION
        """
        route = _route(flask_basic, "do_login")

        effects = tuple(route.body.effects(State.write(scope=StateScope.SESSION)))

        assert [(effect.key, effect.expression) for effect in effects] == [
            ("_user_id", "login_user(current_user)"),
            ("_fresh", "login_user(current_user)"),
            ("_id", "login_user(current_user)"),
            ("_remember", "login_user(current_user)"),
        ]
        assert {effect.category for effect in effects} == {EffectCategory.STATE_WRITE}
        assert all(effect.scope is StateScope.SESSION for effect in effects)
        assert all(effect.location.line > 0 for effect in effects)

    def test_l0_logout_user(self, flask_basic: RepoView) -> None:
        """logout_user() → STATE_WRITE effect (SESSION scope).

        Fixture: flask_basic/app.py::do_logout()
        """
        route = _route(flask_basic, "do_logout")

        effects = tuple(route.body.effects(State.write(scope=StateScope.SESSION)))

        assert [(effect.key, effect.expression) for effect in effects] == [
            ("_user_id", "logout_user()"),
            ("_fresh", "logout_user()"),
            ("_id", "logout_user()"),
            ("_remember", "logout_user()"),
        ]
        assert all(effect.scope is StateScope.SESSION for effect in effects)

    # -- L1: Import aliasing ---------------------------------------------

    def test_l1_aliased_redirect(self, flask_aliased: RepoView) -> None:
        """redir() (alias of redirect) → RESPONSE_WRITE.

        Fixture: flask_aliased/app.py::effect_redirect()
        EXPECT: same as L0 — alias resolves to flask.redirect
        """
        route = _route(flask_aliased, "effect_redirect")

        effect = route.body.effects(Response.write()).one()

        assert effect.category is EffectCategory.RESPONSE_WRITE
        assert effect.expression == 'redir("/")'

    def test_l1_aliased_login_user(self, flask_aliased: RepoView) -> None:
        """sign_in() (alias of login_user) → STATE_WRITE.

        Fixture: flask_aliased/app.py::do_login()
        """
        route = _route(flask_aliased, "do_login")

        effects = tuple(route.body.effects(State.write(scope=StateScope.SESSION)))

        assert [effect.key for effect in effects] == ["_user_id", "_fresh", "_id", "_remember"]
        assert {effect.expression for effect in effects} == {"sign_in(me)"}

    # -- L2: Variable assignment -----------------------------------------

    @pytest.mark.xfail(reason=_EFFECT_CALL_FQN_GAP, strict=True)
    def test_l2_commit_via_variable(self, flask_indirect: RepoView) -> None:
        """db = g.db_session; db.commit() → DB_WRITE.

        Fixture: flask_indirect/app.py::l2_effect_chain()
        EXPECT: L1 resolves db → Session, then matches commit() FQN
        """
        route = _route(flask_indirect, "l2_effect_chain")

        effect = route.body.effects(Db.write()).one()

        assert effect.category is EffectCategory.DB_WRITE
        assert effect.expression == "db.commit()"

    # -- L3: Cross-function same-file ------------------------------------

    def test_l3_effect_in_helper(self, flask_indirect: RepoView) -> None:
        """_write_session("key", val) writes to session → STATE_WRITE.

        Fixture: flask_indirect/app.py::l3_cross_function_effect()
        EXPECT: STATE_WRITE detected via call-graph to _write_session
        """
        route = _route(flask_indirect, "l3_cross_function_effect")

        effect = _assert_effect(
            route,
            EffectCategory.STATE_WRITE,
            scope=StateScope.SESSION,
            expression="session[key]",
            function_contains="_write_session",
        )

        assert effect.key is None

    # -- L4: Cross-file import -------------------------------------------

    def test_l4_effect_in_imported_module(self, flask_indirect: RepoView) -> None:
        """helpers.save_to_session() writes session → STATE_WRITE.

        Fixture: flask_indirect/app.py::l4_cross_file_effect()
        EXPECT: STATE_WRITE from helpers.py included in route scope
        """
        route = _route(flask_indirect, "l4_cross_file_effect")

        effect = _assert_effect(
            route,
            EffectCategory.STATE_WRITE,
            scope=StateScope.SESSION,
            expression="session[key]",
            function_contains="helpers.save_to_session",
        )

        assert effect.key is None

    # -- L5: Subclass method effects -------------------------------------

    @pytest.mark.xfail(reason=_SUBCLASS_EFFECT_GAP, strict=True)
    def test_l5_model_save(self, flask_subclassed: RepoView) -> None:
        """User().save() → DB_WRITE (inherited from Model).

        Fixture: flask_subclassed/app.py::create_user()
        EXPECT: DB_WRITE effect detected via MRO (User → Model → save)
        """
        route = _route(flask_subclassed, "create_user")

        effect = route.body.effects(Db.write()).one()

        assert effect.category is EffectCategory.DB_WRITE
        assert effect.expression == "user.save()"

    @pytest.mark.xfail(reason=_SUBCLASS_EFFECT_GAP, strict=True)
    def test_l5_model_delete(self, flask_subclassed: RepoView) -> None:
        """User().delete() → DB_DELETE (inherited from Model).

        Fixture: flask_subclassed/app.py::delete_user()
        """
        route = _route(flask_subclassed, "delete_user")

        effect = _assert_effect(route, EffectCategory.DB_DELETE, expression="user.delete()")

        assert effect.function.fqn.endswith("delete_user")

    @pytest.mark.xfail(reason=_SUBCLASS_EFFECT_GAP, strict=True)
    def test_l5_different_subclass_save(self, flask_subclassed: RepoView) -> None:
        """Product().save() → same DB_WRITE via same base class.

        Fixture: flask_subclassed/app.py::create_product()
        EXPECT: DB_WRITE — different subclass, same inherited method
        """
        route = _route(flask_subclassed, "create_product")

        effect = route.body.effects(Db.write()).one()

        assert effect.expression == "product.save()"
        assert effect.category is EffectCategory.DB_WRITE

    def test_l5_django_model_save(self, django_basic: RepoView) -> None:
        """Django User().save() → DB_WRITE (inherited from Model).

        Fixture: django_basic/views.py::user_create()
        """
        route = _route(django_basic, "user_create")

        effect = route.body.effects(Db.write()).one()

        assert effect.expression == "user.save()"

    def test_l5_django_model_delete(self, django_basic: RepoView) -> None:
        """Django Article().delete() → DB_DELETE.

        Fixture: django_basic/views.py::ArticleDetailView.delete()
        """
        route = _route_by_handler(django_basic, "ArticleDetailView.delete")

        effect = _assert_effect(route, EffectCategory.DB_DELETE, expression="article.delete()")

        assert effect.function.fqn.endswith("ArticleDetailView.delete")

    @pytest.mark.xfail(reason=_DJANGO_EFFECT_GAP, strict=True)
    def test_l5_django_queryset_ops(self, django_basic: RepoView) -> None:
        """User.objects.all() → DB_READ, .create() → DB_WRITE.

        Fixture: django_basic/views.py
        EXPECT: DB_READ from .all(), DB_WRITE from .create()
        """
        list_route = _route(django_basic, "user_list")
        create_route = _route(django_basic, "user_create")

        assert list_route.body.effects(Db.read()).one().expression == "User.objects.all()"
        assert (
            create_route.body.effects(Db.write()).one().expression
            == "User.objects.create(name=name, email=email)"
        )


# =====================================================================
# EffectAttributePattern — g.user = value
# =====================================================================


class TestEffectAttributePattern:
    """Test detection of attribute-write effects.

    Provider declaration:
        EffectAttributePattern(
            receiver_fqn="flask.globals.g",
            category="STATE_WRITE",
            scope="REQUEST",
        )
    """

    def test_l0_g_attr_write(self, flask_basic: RepoView) -> None:
        """g.user = {"id": 1} → STATE_WRITE effect (REQUEST scope).

        Fixture: flask_basic/app.py::effect_state_write_attr()
        EXPECT: STATE_WRITE with scope=StateScope.REQUEST
        """
        route = _route(flask_basic, "effect_state_write_attr")

        effect = route.body.effects(State.write(scope=StateScope.REQUEST, key="user")).one()

        assert effect.category is EffectCategory.STATE_WRITE
        assert effect.scope is StateScope.REQUEST
        assert effect.key == "user"
        assert effect.expression == "g.user"
        _assert_location(effect)

    def test_l1_aliased_g_write(self, flask_aliased: RepoView) -> None:
        """ctx.user = {"id": 1} where ctx = g → STATE_WRITE.

        Fixture: flask_aliased/app.py::effect_state_attr()
        """
        route = _route(flask_aliased, "effect_state_attr")

        effect = route.body.effects(State.write(scope=StateScope.REQUEST, key="user")).one()

        assert effect.expression == "ctx.user"
        assert effect.category is EffectCategory.STATE_WRITE


# =====================================================================
# EffectSubscriptPattern — session["key"] = value
# =====================================================================


class TestEffectSubscriptPattern:
    """Test detection of subscript-write effects.

    Provider declaration:
        EffectSubscriptPattern(
            receiver_fqn="flask.globals.session",
            category="STATE_WRITE",
            scope="SESSION",
        )
    """

    def test_l0_session_subscript(self, flask_basic: RepoView) -> None:
        """session["user_id"] = 42 → STATE_WRITE (SESSION scope).

        Fixture: flask_basic/app.py::effect_session_write()
        EXPECT: STATE_WRITE with scope=SESSION, key="user_id"
        """
        route = _route(flask_basic, "effect_session_write")

        effects = tuple(route.body.effects(State.write(scope=StateScope.SESSION)))

        assert [(effect.key, effect.expression) for effect in effects] == [
            ("user_id", 'session["user_id"]'),
            ("role", 'session["role"]'),
        ]
        assert all(effect.category is EffectCategory.STATE_WRITE for effect in effects)

    def test_l1_aliased_session(self, flask_aliased: RepoView) -> None:
        """sess["user_id"] = 42 where sess = session → STATE_WRITE.

        Fixture: flask_aliased/app.py::effect_session_write()
        """
        route = _route(flask_aliased, "effect_session_write")

        effect = route.body.effects(State.write(scope=StateScope.SESSION, key="user_id")).one()

        assert effect.expression == 'sess["user_id"]'
        assert effect.scope is StateScope.SESSION

    def test_l2_session_via_variable(self, flask_indirect: RepoView) -> None:
        """s = session; s["role"] = "admin" → STATE_WRITE.

        Fixture: flask_indirect/app.py::l2_session_variable()
        """
        route = _route(flask_indirect, "l2_session_variable")

        effect = route.body.effects(State.write(scope=StateScope.SESSION, key="role")).one()

        assert effect.expression == 's["role"]'
        assert effect.category is EffectCategory.STATE_WRITE


# =====================================================================
# When-predicate discrimination
# =====================================================================


class TestWhenPredicateDiscrimination:
    """Test that when= predicates correctly split call semantics.

    Provider declarations:
        EffectCallPattern(
            fqn="sqlalchemy.orm.Session.execute",
            category="DB_WRITE",
            when=arg(0).type_in("...Insert", "...Update"),
        )
        EffectCallPattern(
            fqn="sqlalchemy.orm.Session.execute",
            category="DB_READ",
            when=arg(0).type_is("...Select"),
        )
    """

    @pytest.mark.xfail(reason=_WHEN_PREDICATE_GAP, strict=True)
    def test_when_insert_is_db_write(self, flask_basic: RepoView) -> None:
        """session.execute(Insert(...)) → DB_WRITE (not DB_READ).

        EXPECT: when= predicate matches arg(0) as Insert → DB_WRITE
        """
        route = _route(flask_basic, "users")

        write = route.body.effects(Db.write()).one()
        reads = tuple(route.body.effects(Db.read()))

        assert write.category is EffectCategory.DB_WRITE
        assert "execute" in write.expression
        assert reads == ()

    @pytest.mark.xfail(reason=_WHEN_PREDICATE_GAP, strict=True)
    def test_when_select_is_db_read(self, flask_basic: RepoView) -> None:
        """session.execute(Select(...)) → DB_READ (not DB_WRITE).

        EXPECT: when= predicate matches arg(0) as Select → DB_READ
        """
        route = _route(flask_basic, "users")

        read = route.body.effects(Db.read()).one()
        writes = tuple(route.body.effects(Db.write()))

        assert read.category is EffectCategory.DB_READ
        assert "execute" in read.expression
        assert writes == ()


# =====================================================================
# Comprehensive: one test per EffectCategory
# =====================================================================


class TestEffectCategoryCompleteness:
    """Ensure every EffectCategory has at least one detection.

    These confirm the full taxonomy is exercised by fixtures + providers.
    """

    def test_db_write_detected(self, flask_basic: RepoView) -> None:
        """At least one DB_WRITE effect detected."""
        effect = _assert_repo_effect(flask_basic, EffectCategory.DB_WRITE)

        db_write_effects = tuple(
            effect for route in flask_basic.routes for effect in route.body.effects(Db.write())
        )
        assert effect in db_write_effects

    @pytest.mark.xfail(reason=_SUBCLASS_EFFECT_GAP, strict=True)
    def test_db_delete_detected(self, flask_subclassed: RepoView) -> None:
        """At least one DB_DELETE effect detected."""
        effect = _assert_repo_effect(flask_subclassed, EffectCategory.DB_DELETE)

        assert effect.category is EffectCategory.DB_DELETE

    def test_db_read_detected(self, flask_basic: RepoView) -> None:
        """At least one DB_READ effect detected."""
        effect = _assert_repo_effect(flask_basic, EffectCategory.DB_READ)

        assert effect.category is EffectCategory.DB_READ

    def test_state_write_detected(self, flask_basic: RepoView) -> None:
        """At least one session/request-scoped STATE_WRITE effect detected.

        Asserts the *scoped* (provider-modeled session/request) write exists
        rather than that the first STATE_WRITE happens to be one: FLAW-281a also
        infers conservative SERVER-scoped STATE_WRITEs for custom mutating calls
        (e.g. ``f.save(path)``), which are legitimate and may be enumerated first.
        """
        scoped = [
            effect
            for effect in _all_effects(flask_basic)
            if effect.category is EffectCategory.STATE_WRITE
            and effect.scope in {StateScope.REQUEST, StateScope.SESSION}
        ]
        assert scoped, "expected a request/session-scoped STATE_WRITE effect"

    def test_response_write_detected(self, flask_basic: RepoView) -> None:
        """At least one RESPONSE_WRITE effect detected."""
        effect = _assert_repo_effect(flask_basic, EffectCategory.RESPONSE_WRITE)

        response_effects = tuple(
            effect
            for route in flask_basic.routes
            for effect in route.body.effects(Response.write())
        )
        assert effect in response_effects

    def test_config_write_detected(self, flask_basic: RepoView) -> None:
        """At least one CONFIG_WRITE effect detected."""
        route = _route(flask_basic, "effect_config_write")

        effect = route.body.effects(Config.write()).one()

        assert effect.category is EffectCategory.CONFIG_WRITE
        assert effect.expression == 'app.config["DEBUG"]'


class TestStateScopeCompleteness:
    """Ensure each StateScope is tested with state effects."""

    def test_request_scope(self, flask_basic: RepoView) -> None:
        """STATE_WRITE with scope=REQUEST (g.user = ...)."""
        route = _route(flask_basic, "effect_state_write_attr")

        effect = route.body.effects(State.write(scope=StateScope.REQUEST)).one()

        assert effect.scope is StateScope.REQUEST
        assert effect.category is EffectCategory.STATE_WRITE

    def test_session_scope(self, flask_basic: RepoView) -> None:
        """STATE_WRITE with scope=SESSION (session["key"] = ...)."""
        route = _route(flask_basic, "effect_session_write")

        effects = tuple(route.body.effects(State.write(scope=StateScope.SESSION)))

        assert {effect.key for effect in effects} == {"user_id", "role"}
        assert all(effect.scope is StateScope.SESSION for effect in effects)
