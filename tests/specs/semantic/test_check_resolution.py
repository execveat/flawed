"""EP-4/EP-9: Security check resolution tests.

Tests that the Semantic API correctly detects security guards declared
by providers.

Pattern types under test:
  - SecurityCheckPattern (DECORATOR, CALL, METHOD_CALL kinds)
  - ClassAttributeGuardPattern (DRF permission_classes, etc.)
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from flawed._index import CodeIndex
from flawed._index._types import (
    CallEdge,
    ClassRecord,
    EdgeSource,
    ExtractionProvenance,
    FlowKind,
    FunctionKind,
    FunctionRecord,
    ImportFact,
    ResolutionStatus,
    SourceSpan,
    SymbolRef,
    ValueFlowEdge,
)
from flawed.conditions import ConditionKind
from flawed.flow import ValueHandle

if TYPE_CHECKING:
    from flawed.conditions import Condition
    from flawed.repo import RepoView
    from flawed.route import Route


_PROV = ExtractionProvenance("test", "0", "")


def _span(line: int, *, file: str = "views.py", column: int = 0) -> SourceSpan:
    return SourceSpan(file=file, line=line, column=column, end_line=line, end_column=column + 1)


def _route(repo: RepoView, endpoint: str) -> Route:
    matches = tuple(route for route in repo.routes if route.endpoint == endpoint)
    assert matches, f"route endpoint {endpoint!r} was not discovered"
    assert len(matches) == 1, f"expected one route for endpoint {endpoint!r}, got {len(matches)}"
    return matches[0]


def _function_conditions(repo: RepoView, function_name: str) -> tuple[Condition, ...]:
    for function in repo.functions:
        if function.name == function_name:
            return tuple(function.body.conditions())
    raise AssertionError(f"function {function_name!r} was not discovered")


def _assert_check(
    conditions: tuple[Condition, ...],
    category: str,
    expression_fragment: str,
) -> Condition:
    for condition in conditions:
        if (
            getattr(condition, "category", None) == category
            and expression_fragment in condition.expression
        ):
            assert condition.guard is not None
            return condition
    seen = [
        (condition.expression, getattr(condition, "category", None)) for condition in conditions
    ]
    raise AssertionError(f"expected {category}:{expression_fragment!r}; saw {seen}")


def _empty_index(
    *,
    imports: tuple[ImportFact, ...],
    functions: tuple[FunctionRecord, ...],
    classes: tuple[ClassRecord, ...],
    call_edges: tuple[CallEdge, ...] = (),
    value_flow_edges: tuple[ValueFlowEdge, ...] = (),
    symbol_refs: tuple[SymbolRef, ...] = (),
) -> CodeIndex:
    return CodeIndex(
        repo_root=Path(),
        functions=functions,
        classes=classes,
        decorators=(),
        imports=imports,
        attributes=(),
        call_edges=call_edges,
        cfgs={},
        value_flow_edges=value_flow_edges,
        symbol_refs=symbol_refs,
        errors=(),
        provenance=_PROV,
    )


def _import(module: str) -> ImportFact:
    return ImportFact(
        module=module,
        names=(),
        aliases=(),
        is_from_import=False,
        location=_span(1),
        provenance=_PROV,
    )


def _symbol(name: str, fqn: str, line: int = 1) -> SymbolRef:
    return SymbolRef(
        name=name,
        fqn=fqn,
        resolution=ResolutionStatus.RESOLVED,
        location=_span(line),
        provenance=_PROV,
    )


def _function(
    fqn: str,
    name: str,
    line: int,
    *,
    parent_class: str | None = None,
) -> FunctionRecord:
    return FunctionRecord(
        fqn=fqn,
        name=name,
        file="views.py",
        line=line,
        params=(),
        decorator_names=(),
        decorator_fqns=(),
        kind=FunctionKind.METHOD if parent_class else FunctionKind.TOP_LEVEL,
        is_method=parent_class is not None,
        is_nested=False,
        is_async=False,
        parent_class=parent_class,
        location=_span(line),
        provenance=_PROV,
    )


def _class(
    fqn: str,
    name: str,
    line: int,
    *,
    bases: tuple[str, ...],
    class_var_names: tuple[str, ...] = (),
    method_names: tuple[str, ...] = (),
) -> ClassRecord:
    return ClassRecord(
        fqn=fqn,
        name=name,
        file="views.py",
        bases=bases,
        mro_chain=(fqn,),
        mro_complete=False,
        method_names=method_names,
        class_var_names=class_var_names,
        is_abstract=False,
        metaclass=None,
        subclasses=(),
        all_subclasses=(),
        inherited_methods=(),
        hierarchy_gaps=(),
        location=SourceSpan("views.py", line, 0, line + 10, 0),
        provenance=_PROV,
    )


# =====================================================================
# SecurityCheckPattern — DECORATOR kind
# =====================================================================


class TestSecurityCheckDecorator:
    """Test detection of decorator-based security checks.

    Provider declaration:
        SecurityCheckPattern(
            fqn="flask_login.login_required",
            kind=CheckKind.DECORATOR,
            category="AUTHENTICATION",
        )
    """

    def test_l0_login_required(self, flask_basic: RepoView) -> None:
        """@login_required on route → route has AUTHENTICATION check.

        Fixture: flask_basic/app.py::check_auth_decorator()
        EXPECT: route "/checks/protected" has AUTHENTICATION guard
        """
        route = _route(flask_basic, "check_auth_decorator")

        _assert_check(tuple(route.body.conditions()), "AUTHENTICATION", "@login_required")

    def test_l0_unprotected_route(self, flask_basic: RepoView) -> None:
        """Route without @login_required → no AUTHENTICATION check.

        Fixture: flask_basic/app.py::index()
        EXPECT: route "/" has NO auth guard
        """
        route = _route(flask_basic, "index")

        conditions = tuple(route.body.conditions())

        assert not any(
            getattr(condition, "category", None) == "AUTHENTICATION" for condition in conditions
        )

    def test_l1_aliased_decorator(self, flask_aliased: RepoView) -> None:
        """@auth_required (alias of @login_required) → AUTHENTICATION.

        Fixture: flask_aliased/app.py::check_auth()
        EXPECT: same detection as L0
        """
        route = _route(flask_aliased, "check_auth")

        _assert_check(tuple(route.body.conditions()), "AUTHENTICATION", "@auth_required")

    def test_l0_django_login_required(self, django_basic: RepoView) -> None:
        """Django @login_required → AUTHENTICATION check.

        Fixture: django_basic/views.py::user_list()
        """
        _assert_check(
            _function_conditions(django_basic, "user_list"),
            "AUTHENTICATION",
            "@login_required",
        )

    def test_l0_django_permission_required(self, django_basic: RepoView) -> None:
        """Django @permission_required → AUTHORIZATION check.

        Fixture: django_basic/views.py::search()
        """
        _assert_check(
            _function_conditions(django_basic, "search"),
            "AUTHORIZATION",
            "@permission_required",
        )

    def test_l0_django_require_http_methods(self, django_basic: RepoView) -> None:
        """Django @require_http_methods → METHOD_RESTRICTION check.

        Fixture: django_basic/views.py::user_create()
        """
        _assert_check(
            _function_conditions(django_basic, "user_create"),
            "METHOD_RESTRICTION",
            "@require_http_methods",
        )


# =====================================================================
# SecurityCheckPattern — CALL kind
# =====================================================================


class TestSecurityCheckCall:
    """Test detection of call-based security checks.

    Provider declaration:
        SecurityCheckPattern(
            fqn="werkzeug.security.check_password_hash",
            kind=CheckKind.CALL,
            category="PASSWORD_VERIFY",
        )
    """

    def test_l0_check_password_hash(self, flask_basic: RepoView) -> None:
        """check_password_hash(hash, pw) → PASSWORD_VERIFY check.

        Fixture: flask_basic/app.py::check_password()
        EXPECT: PASSWORD_VERIFY check in route scope
        """
        route = _route(flask_basic, "check_password")

        _assert_check(
            tuple(route.body.conditions()),
            "PASSWORD_VERIFY",
            "check_password_hash(stored_hash, pw)",
        )

    def test_l0_generate_password_hash(self, flask_basic: RepoView) -> None:
        """generate_password_hash(pw) → PASSWORD_HASH check.

        Fixture: flask_basic/app.py::check_hash()
        """
        route = _route(flask_basic, "check_hash")

        _assert_check(
            tuple(route.body.conditions()),
            "PASSWORD_HASH",
            "generate_password_hash(pw)",
        )

    def test_l1_aliased_password_check(self, flask_aliased: RepoView) -> None:
        """verify_pw() alias → PASSWORD_VERIFY.

        Fixture: flask_aliased/app.py::check_password()
        """
        route = _route(flask_aliased, "check_password")

        _assert_check(tuple(route.body.conditions()), "PASSWORD_VERIFY", 'verify_pw("hash", pw)')

    def test_l1_aliased_password_hash(self, flask_aliased: RepoView) -> None:
        """hash_pw() alias → PASSWORD_HASH.

        Fixture: flask_aliased/app.py::check_hash()
        """
        route = _route(flask_aliased, "check_hash")

        _assert_check(tuple(route.body.conditions()), "PASSWORD_HASH", "hash_pw(pw)")


# =====================================================================
# SecurityCheckPattern — METHOD_CALL kind
# =====================================================================


class TestSecurityCheckMethodCall:
    """Test detection of method-call security checks.

    Provider declaration:
        SecurityCheckPattern(
            fqn="flask_wtf.FlaskForm.validate_on_submit",
            kind=CheckKind.METHOD_CALL,
            category="CSRF|FORM_VALIDATION",
        )
    """

    def test_l5_validate_on_submit(self, flask_subclassed: RepoView) -> None:
        """form.validate_on_submit() on FlaskForm subclass → CSRF check.

        Fixture: flask_subclassed/app.py::register()
        EXPECT: CSRF|FORM_VALIDATION check detected via MRO
        """
        from flawed._semantic import WebApp

        function = _function("app.views.register", "register", 20)
        form_class = _class(
            "app.views.RegistrationForm",
            "RegistrationForm",
            5,
            bases=("FlaskForm",),
        )
        idx = _empty_index(
            imports=(_import("flask_wtf"),),
            functions=(function,),
            classes=(form_class,),
            call_edges=(
                CallEdge(
                    caller_fqn=function.fqn,
                    callee_fqn="app.views.register.<locals>.form.validate_on_submit",
                    arguments=(),
                    resolution=ResolutionStatus.RESOLVED,
                    source=EdgeSource.AST,
                    unresolved_reason=None,
                    location=_span(22),
                    provenance=_PROV,
                    call_expression="form.validate_on_submit",
                ),
            ),
            value_flow_edges=(
                ValueFlowEdge(
                    source_expr="RegistrationForm()",
                    source_location=_span(21),
                    target_expr="form",
                    target_location=_span(21),
                    kind=FlowKind.ASSIGN,
                    containing_function_fqn=function.fqn,
                    provenance=_PROV,
                ),
            ),
            symbol_refs=(
                _symbol("FlaskForm", "flask_wtf.FlaskForm", 5),
                _symbol("RegistrationForm", form_class.fqn, 21),
            ),
        )

        repo = WebApp.from_index(idx).repo_view()

        _assert_check(
            _function_conditions(repo, "register"),
            "CSRF|FORM_VALIDATION",
            "validate_on_submit",
        )

    def test_validate_on_submit_via_self_form_factory(self) -> None:
        """``form = self.form(); form.validate_on_submit()`` is credited when the
        view's ``form`` class attribute is a FlaskForm subclass (FLAW-274).

        Models a real-world idiom (a ``Login.post`` MethodView): a MethodView
        subclass declares ``form = LoginForm`` (the form *class*) and instantiates
        it via ``self.form()``.  FLAW-279 delivered constructor + annotation
        receiver typing, but not this method-call / class-attribute indirection,
        so the validation went unrecognised -> a ~59-finding FP cluster on a real app.
        EXPECT: CSRF|FORM_VALIDATION check detected through the self.form() factory.
        """
        from flawed._semantic import WebApp

        view_class = _class(
            "app.views.Login",
            "Login",
            20,
            bases=("MethodView",),
            class_var_names=("form",),
            method_names=("post",),
        )
        form_class = _class(
            "app.views.LoginForm",
            "LoginForm",
            1,
            bases=("FlaskForm",),
        )
        post = _function("app.views.Login.post", "post", 22, parent_class=view_class.fqn)
        idx = _empty_index(
            imports=(_import("flask_wtf"),),
            functions=(post,),
            classes=(view_class, form_class),
            call_edges=(
                CallEdge(
                    caller_fqn=post.fqn,
                    callee_fqn="app.views.Login.post.<locals>.form.validate_on_submit",
                    arguments=(),
                    resolution=ResolutionStatus.RESOLVED,
                    source=EdgeSource.AST,
                    unresolved_reason=None,
                    location=_span(24),
                    provenance=_PROV,
                    call_expression="form.validate_on_submit",
                ),
            ),
            value_flow_edges=(
                # class attribute: ``form = LoginForm`` (the form CLASS, no parens)
                ValueFlowEdge(
                    source_expr="LoginForm",
                    source_location=_span(21),
                    target_expr="form",
                    target_location=_span(21),
                    kind=FlowKind.ASSIGN,
                    containing_function_fqn=None,
                    provenance=_PROV,
                ),
                # local factory call: ``form = self.form()``
                ValueFlowEdge(
                    source_expr="self.form()",
                    source_location=_span(23),
                    target_expr="form",
                    target_location=_span(23),
                    kind=FlowKind.ASSIGN,
                    containing_function_fqn=post.fqn,
                    provenance=_PROV,
                ),
            ),
            symbol_refs=(
                _symbol("FlaskForm", "flask_wtf.FlaskForm", 1),
                _symbol("LoginForm", form_class.fqn, 21),
            ),
        )

        repo = WebApp.from_index(idx).repo_view()

        _assert_check(
            _function_conditions(repo, "post"),
            "CSRF|FORM_VALIDATION",
            "validate_on_submit",
        )

    def test_self_form_factory_non_form_class_not_recognised(self) -> None:
        """``form = self.form()`` where ``form`` is bound to a non-FlaskForm class
        is NOT credited as validation (FLAW-274 resolve-or-gap / FN-safety).

        The whole point of recognition is FP reduction that must never raise a
        false negative: an unproven receiver leaves the missing-validation finding
        firing.  Here ``form = PlainThing`` (a plain class) must NOT be mistaken
        for a validation gate.
        """
        from flawed._semantic import WebApp

        view_class = _class(
            "app.views.Widget",
            "Widget",
            20,
            bases=("MethodView",),
            class_var_names=("form",),
            method_names=("post",),
        )
        plain_class = _class(
            "app.views.PlainThing",
            "PlainThing",
            1,
            bases=("object",),
        )
        post = _function("app.views.Widget.post", "post", 22, parent_class=view_class.fqn)
        idx = _empty_index(
            imports=(_import("flask_wtf"),),
            functions=(post,),
            classes=(view_class, plain_class),
            call_edges=(
                CallEdge(
                    caller_fqn=post.fqn,
                    callee_fqn="app.views.Widget.post.<locals>.form.validate_on_submit",
                    arguments=(),
                    resolution=ResolutionStatus.RESOLVED,
                    source=EdgeSource.AST,
                    unresolved_reason=None,
                    location=_span(24),
                    provenance=_PROV,
                    call_expression="form.validate_on_submit",
                ),
            ),
            value_flow_edges=(
                ValueFlowEdge(
                    source_expr="PlainThing",
                    source_location=_span(21),
                    target_expr="form",
                    target_location=_span(21),
                    kind=FlowKind.ASSIGN,
                    containing_function_fqn=None,
                    provenance=_PROV,
                ),
                ValueFlowEdge(
                    source_expr="self.form()",
                    source_location=_span(23),
                    target_expr="form",
                    target_location=_span(23),
                    kind=FlowKind.ASSIGN,
                    containing_function_fqn=post.fqn,
                    provenance=_PROV,
                ),
            ),
            symbol_refs=(_symbol("PlainThing", plain_class.fqn, 21),),
        )

        repo = WebApp.from_index(idx).repo_view()

        conditions = _function_conditions(repo, "post")
        assert not any(
            getattr(condition, "category", None) == "CSRF|FORM_VALIDATION"
            for condition in conditions
        ), (
            "an unproven self.form() receiver must not be credited as validation; "
            f"saw {[(c.expression, getattr(c, 'category', None)) for c in conditions]}"
        )


# =====================================================================
# ClassAttributeGuardPattern — DRF permission_classes, etc.
# =====================================================================


class TestClassAttributeGuardPattern:
    """Test detection of class-attribute security configuration.

    Provider declaration:
        ClassAttributeGuardPattern(
            view_base_fqn="rest_framework.views.APIView",
            attribute_name="permission_classes",
            guard_base_fqn="rest_framework.permissions.BasePermission",
            category="AUTHORIZATION",
            empty_means_unprotected=True,
        )

    Note: DRF fixtures are not yet created, so these tests document
    the expected behavior for when they are added.
    """

    def test_l5_permission_classes_list(self) -> None:
        """permission_classes = [IsAuthenticated] → AUTHORIZATION guard.

        EXPECT: engine scans APIView subclasses for permission_classes attr,
                resolves each entry against BasePermission hierarchy,
                labels them as AUTHORIZATION guards
        """
        from flawed._semantic import WebApp

        view_class = _class(
            "app.views.UserView",
            "UserView",
            5,
            bases=("APIView",),
            class_var_names=("permission_classes",),
            method_names=("get",),
        )
        permission_class = _class(
            "app.views.IsOwner",
            "IsOwner",
            20,
            bases=("BasePermission",),
        )
        method = _function("app.views.UserView.get", "get", 10, parent_class=view_class.fqn)
        idx = _empty_index(
            imports=(_import("rest_framework.views"),),
            functions=(method,),
            classes=(view_class, permission_class),
            value_flow_edges=(
                ValueFlowEdge(
                    source_expr="[IsOwner]",
                    source_location=_span(6),
                    target_expr="permission_classes",
                    target_location=_span(6),
                    kind=FlowKind.ASSIGN,
                    containing_function_fqn=None,
                    provenance=_PROV,
                ),
            ),
            symbol_refs=(
                _symbol("APIView", "rest_framework.views.APIView", 5),
                _symbol("BasePermission", "rest_framework.permissions.BasePermission", 20),
                _symbol("IsOwner", permission_class.fqn, 6),
            ),
        )

        repo = WebApp.from_index(idx).repo_view()

        _assert_check(_function_conditions(repo, "get"), "AUTHORIZATION", "permission_classes")

    def test_l5_empty_permission_classes(self) -> None:
        """permission_classes = [] → unprotected (empty_means_unprotected=True).

        EXPECT: engine flags this as a route with no AUTHORIZATION guard
        """
        from flawed._semantic import WebApp

        view_class = _class(
            "app.views.OpenView",
            "OpenView",
            5,
            bases=("APIView",),
            class_var_names=("permission_classes",),
            method_names=("get",),
        )
        method = _function("app.views.OpenView.get", "get", 10, parent_class=view_class.fqn)
        idx = _empty_index(
            imports=(_import("rest_framework.views"),),
            functions=(method,),
            classes=(view_class,),
            value_flow_edges=(
                ValueFlowEdge(
                    source_expr="[]",
                    source_location=_span(6),
                    target_expr="permission_classes",
                    target_location=_span(6),
                    kind=FlowKind.ASSIGN,
                    containing_function_fqn=None,
                    provenance=_PROV,
                ),
            ),
            symbol_refs=(_symbol("APIView", "rest_framework.views.APIView", 5),),
        )

        repo = WebApp.from_index(idx).repo_view()

        assert not _function_conditions(repo, "get")


# =====================================================================
# Cross-cutting: check coverage analysis
# =====================================================================


class TestCheckCoverageAnalysis:
    """Test the engine's ability to report auth coverage per route.

    For any rule that depends on check coverage, the key question is:
    "Is this route protected by the right check?"
    """

    def test_protected_vs_unprotected_routes(self, flask_basic: RepoView) -> None:
        """Some routes have @login_required, others don't.

        EXPECT: the analysis can distinguish protected from unprotected
        """
        protected = _route(flask_basic, "check_auth_decorator")
        unprotected = _route(flask_basic, "index")

        assert tuple(protected.body.conditions())
        assert not tuple(unprotected.body.conditions())

    def test_check_on_route_scope(self, flask_basic: RepoView) -> None:
        """Security check is in scope for a specific route, not global.

        EXPECT: @login_required on one route doesn't protect others
        """
        protected = _route(flask_basic, "check_auth_decorator")
        sibling = _route(flask_basic, "check_password")

        _assert_check(tuple(protected.body.conditions()), "AUTHENTICATION", "@login_required")
        assert not any(
            getattr(condition, "category", None) == "AUTHENTICATION"
            for condition in sibling.body.conditions()
        )


# =====================================================================
# Structural conditions from control-flow
# =====================================================================


class TestStructuralConditions:
    """Test CFG-backed ``scope.conditions()`` and collection filters."""

    def test_cfg_condition_is_available_on_route_scope(self, flask_basic: RepoView) -> None:
        route = _route(flask_basic, "users")

        condition = route.body.conditions().comparing("request.method", "*POST*").one()

        assert condition.expression == 'request.method == "POST"'
        assert condition.kind is ConditionKind.COMPARISON
        assert condition.operator == "=="
        assert condition.left is not None
        assert condition.left.expression == "request.method"
        assert condition.right is not None
        assert "POST" in condition.right.expression
        assert condition.guard is None

    def test_structural_condition_is_not_returned_as_security_check(
        self,
        flask_basic: RepoView,
    ) -> None:
        route = _route(flask_basic, "users")

        assert tuple(route.body.conditions().comparing("request.method", "*POST*"))
        assert tuple(route.body.checks()) == ()

    def test_conditions_using_matches_operands_and_expression(
        self,
        flask_basic: RepoView,
    ) -> None:
        route = _route(flask_basic, "users")
        value = ValueHandle(location=route.location, expression="request.method")

        conditions = route.body.conditions_using(value)

        assert len(conditions) == 1
        assert conditions.one().expression == 'request.method == "POST"'
