"""EP-8b: Taint sink detection tests.

Tests that the Semantic API correctly identifies injection sinks
declared by providers, with proper when-predicate evaluation.

Pattern type under test:
  - TaintSinkPattern (SQL injection, SSTI, XSS, etc.)
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from flawed.inputs import Form, InputSource, Query

if TYPE_CHECKING:
    from flawed.repo import RepoView
    from flawed.route import Route

pytestmark = pytest.mark.slow


def _route(repo: RepoView, endpoint: str) -> Route:
    return repo.routes.where(lambda route: route.endpoint == endpoint).one()


def _sinks(repo: RepoView, endpoint: str, kind: str) -> list[object]:
    return list(_route(repo, endpoint).reachable.sinks(kind=kind))


def _assert_input_flows_to_sink(
    repo: RepoView,
    *,
    endpoint: str,
    input_source: InputSource,
    sink_kind: str,
    expression_fragment: str,
) -> None:
    route = _route(repo, endpoint)
    read = route.body.reads(input_source).one()
    sinks = list(route.reachable.sinks(kind=sink_kind))

    assert len(sinks) == 1
    assert sinks[0].kind == sink_kind
    assert expression_fragment in sinks[0].expression
    assert read.value.flows_to(sinks[0].target)


# =====================================================================
# TaintSinkPattern
# =====================================================================


class TestTaintSinkPattern:
    """Test detection of injection sinks.

    Provider declaration:
        TaintSinkPattern(
            fqn="sqlalchemy.text",
            arg=0,
            sink_kind="SQL_INJECTION",
            when=~arg(0).is_literal_string(),
        )
    """

    # -- SQL injection ---------------------------------------------------

    def test_l0_text_with_user_input(self, flask_basic: RepoView) -> None:
        """text(user_input) → SQL_INJECTION sink flagged.

        Fixture: flask_basic/app.py::sink_sql_injection()
        EXPECT: SQL_INJECTION sink detected at text() call
        EXPECT: when= predicate satisfied (~is_literal_string)
        """
        route = _route(flask_basic, "sink_sql_injection")
        read = route.body.reads(Form()).one()
        sinks = list(route.reachable.sinks(kind="SQL_INJECTION"))

        assert len(sinks) == 1
        assert sinks[0].kind == "SQL_INJECTION"
        assert read.value.flows_to(sinks[0].target)

    def test_l0_text_with_literal(self, flask_basic: RepoView) -> None:
        """text("SELECT 1") → NOT flagged (when= excludes literals).

        Fixture: flask_basic/app.py::sink_sql_safe()
        EXPECT: no SQL_INJECTION sink — arg is a literal string
        """
        assert _sinks(flask_basic, "sink_sql_safe", "SQL_INJECTION") == []

    # -- SSTI ------------------------------------------------------------

    def test_l0_render_template_string(self, flask_basic: RepoView) -> None:
        """render_template_string(user_input) → SSTI sink.

        Fixture: flask_basic/app.py::sink_ssti()
        """
        route = _route(flask_basic, "sink_ssti")
        read = route.body.reads(Form()).one()
        sinks = list(route.reachable.sinks(kind="SSTI"))

        assert len(sinks) == 1
        assert read.value.flows_to(sinks[0].target)

    # -- XSS -------------------------------------------------------------

    def test_l0_markup_bypass(self, flask_basic: RepoView) -> None:
        """Markup(user_input) → XSS sink (autoescaping bypass).

        Fixture: flask_basic/app.py::sink_xss()
        """
        route = _route(flask_basic, "sink_xss")
        read = route.body.reads(Query()).one()
        sinks = list(route.reachable.sinks(kind="XSS"))

        assert len(sinks) == 1
        assert read.value.flows_to(sinks[0].target)

    # -- Open redirect ---------------------------------------------------

    def test_l0_redirect_user_input(self, flask_basic: RepoView) -> None:
        """redirect(user_input) → OPEN_REDIRECT sink.

        Fixture: flask_basic/app.py::sink_open_redirect()
        """
        route = _route(flask_basic, "sink_open_redirect")
        read = route.body.reads(Query()).one()
        sinks = list(route.reachable.sinks(kind="OPEN_REDIRECT"))

        assert len(sinks) == 1
        assert read.value.flows_to(sinks[0].target)

    # -- Command injection -----------------------------------------------

    def test_l0_os_system_user_input(self, flask_basic: RepoView) -> None:
        """os.system(user_input) → COMMAND_INJECTION sink.

        Fixture: flask_basic/app.py::sink_os_system()
        """
        _assert_input_flows_to_sink(
            flask_basic,
            endpoint="sink_os_system",
            input_source=Query(),
            sink_kind="COMMAND_INJECTION",
            expression_fragment="os.system",
        )

    def test_l0_subprocess_run_user_input(self, flask_basic: RepoView) -> None:
        """subprocess.run(user_input) → COMMAND_INJECTION sink.

        Fixture: flask_basic/app.py::sink_subprocess_run()
        """
        _assert_input_flows_to_sink(
            flask_basic,
            endpoint="sink_subprocess_run",
            input_source=Query(),
            sink_kind="COMMAND_INJECTION",
            expression_fragment="subprocess.run",
        )

    # -- Code injection ---------------------------------------------------

    def test_l0_eval_user_input(self, flask_basic: RepoView) -> None:
        """eval(user_input) → CODE_INJECTION sink.

        Fixture: flask_basic/app.py::sink_eval()
        """
        _assert_input_flows_to_sink(
            flask_basic,
            endpoint="sink_eval",
            input_source=Query(),
            sink_kind="CODE_INJECTION",
            expression_fragment="eval",
        )

    def test_l0_exec_user_input(self, flask_basic: RepoView) -> None:
        """exec(user_input) → CODE_INJECTION sink.

        Fixture: flask_basic/app.py::sink_exec()
        """
        _assert_input_flows_to_sink(
            flask_basic,
            endpoint="sink_exec",
            input_source=Query(),
            sink_kind="CODE_INJECTION",
            expression_fragment="exec",
        )

    # -- Django sinks ----------------------------------------------------

    _DJANGO_SINK_GAP = (
        "P3.3-GAP-03/P6.4-GAP [blocked-on: L1-H04/L1-H05]: Django sinks "
        "are flow-gated and require InputRead detection, which needs type "
        "enrichment for HttpRequest attribute FQN resolution."
    )

    @pytest.mark.xfail(
        reason=_DJANGO_SINK_GAP,
        strict=True,
    )
    def test_l0_django_mark_safe(self, django_basic: RepoView) -> None:
        """mark_safe(user_input) → XSS sink.

        Fixture: django_basic/views.py::unsafe_view()
        """
        sinks = _sinks(django_basic, "unsafe_view", "XSS")
        assert len(sinks) == 1

    @pytest.mark.xfail(
        reason=_DJANGO_SINK_GAP,
        strict=True,
    )
    def test_l0_django_redirect(self, django_basic: RepoView) -> None:
        """redirect(user_input) → OPEN_REDIRECT sink.

        Fixture: django_basic/views.py::redirect_view()
        """
        sinks = _sinks(django_basic, "redirect_view", "OPEN_REDIRECT")
        assert len(sinks) == 1

    # -- Aliased sinks ---------------------------------------------------

    def test_l1_aliased_text(self, flask_aliased: RepoView) -> None:
        """raw_sql(query) where raw_sql = text → SQL_INJECTION.

        Fixture: flask_aliased/app.py::sink_sqli()
        EXPECT: alias resolves to sqlalchemy.text
        """
        sinks = _sinks(flask_aliased, "sink_sqli", "SQL_INJECTION")
        assert len(sinks) == 1

    # -- Cross-function sinks --------------------------------------------

    def test_l3_sink_in_helper(self, flask_indirect: RepoView) -> None:
        """_run_query(query_str) calls text(query_str) → sink detected.

        Fixture: flask_indirect/app.py::l3_cross_function_sink()
        EXPECT: SQL_INJECTION at text() inside _run_query()
        """
        route = _route(flask_indirect, "l3_cross_function_sink")
        read = route.body.reads(Form()).one()
        sinks = list(route.reachable.sinks(kind="SQL_INJECTION"))

        assert len(sinks) == 1
        assert read.value.flows_to(sinks[0].target)

    def test_l4_sink_in_imported_helper(self, flask_indirect: RepoView) -> None:
        """helpers.execute_raw(query) calls text(query) → sink detected.

        Fixture: flask_indirect/app.py::l4_cross_file_sink()
        """
        route = _route(flask_indirect, "l4_cross_file_sink")
        read = route.body.reads(Form()).one()
        sinks = list(route.reachable.sinks(kind="SQL_INJECTION"))

        assert len(sinks) == 1
        assert read.value.flows_to(sinks[0].target)


# =====================================================================
# When-predicate evaluation
# =====================================================================


class TestWhenPredicateEvaluation:
    """Test that when= predicates correctly gate sink detection."""

    def test_literal_string_predicate_true(self, flask_basic: RepoView) -> None:
        """arg(0).is_literal_string() → True for string literal arg.

        text("SELECT 1") — arg 0 is a literal → predicate True
        ~is_literal_string → False → sink NOT flagged
        """
        assert _sinks(flask_basic, "sink_sql_safe", "SQL_INJECTION") == []

    def test_literal_string_predicate_false(self, flask_basic: RepoView) -> None:
        """arg(0).is_literal_string() → False for variable arg.

        query = request.form["q"]; text(query) — arg 0 is variable
        ~is_literal_string → True → sink IS flagged
        """
        assert len(_sinks(flask_basic, "sink_sql_injection", "SQL_INJECTION")) == 1
