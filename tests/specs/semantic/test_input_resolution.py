"""EP-2: Input source resolution tests.

Tests that the Semantic API correctly detects input reads declared by
providers, across all complexity levels and pattern types.

Pattern types under test:
  - InputAttributePattern (request.args, request.form, etc.)
  - InputMethodPattern (request.get_json(), etc.)
  - InputFieldAccessPattern (form.field.data)
  - InputParameterPattern (FastAPI Query(), Body(), etc.)
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import pytest

from flawed.core import Key
from flawed.inputs import (
    AccessPattern,
    Cardinality,
    Cookie,
    DependencyInput,
    FileUpload,
    Form,
    Header,
    InputRead,
    InputValueType,
    Json,
    PathParam,
    Query,
    RawBody,
)

if TYPE_CHECKING:
    from flawed.repo import RepoView
    from flawed.route import Route


def _routes_by_endpoint(repo: RepoView) -> dict[str, Route]:
    """Build endpoint → route mapping for assertion convenience."""
    return {r.endpoint: r for r in repo.routes}


# =====================================================================
# InputAttributePattern — request.args, request.form, etc.
# =====================================================================


class TestInputAttributePattern:
    """Test detection of attribute-access input patterns.

    Provider declaration:
        InputAttributePattern(
            receiver_fqn="flask.globals.request",
            attribute="args",
            source_type="Query",
        )

    The engine must detect ``request.args`` accesses and label them
    as Query input reads.
    """

    # -- L0: Direct usage ------------------------------------------------

    def test_l0_request_args_direct(self, flask_basic: RepoView) -> None:
        """request.args.get("user_id") → detected as Query read.

        Fixture: flask_basic/app.py::input_query()
        EXPECT: one Query read with key=Key("user_id")
        """
        routes = _routes_by_endpoint(flask_basic)
        route = routes["input_query"]
        reads = list(route.body.reads(Query()))

        assert len(reads) == 1
        assert reads[0].source == Query(key=Key("user_id"))
        assert reads[0].access_pattern is AccessPattern.GET
        assert reads[0].cardinality is Cardinality.SINGLE

    def test_l0_request_form_subscript(self, flask_basic: RepoView) -> None:
        """request.form["name"] → detected as Form read.

        Fixture: flask_basic/app.py::input_form()
        EXPECT: Form read with key=Key("name"), access_pattern=SUBSCRIPT
        """
        routes = _routes_by_endpoint(flask_basic)
        route = routes["input_form"]
        reads = list(route.body.reads(Form()))

        assert len(reads) == 2
        sources = {r.source for r in reads}
        assert Form(key=Key("name")) in sources
        assert Form(key=Key("email")) in sources
        # name uses subscript, email uses .get()
        by_key = {cast("Form", r.source).key: r for r in reads}
        assert by_key[Key("name")].access_pattern is AccessPattern.SUBSCRIPT
        assert by_key[Key("email")].access_pattern is AccessPattern.GET

    def test_l0_request_json_attribute(self, flask_basic: RepoView) -> None:
        """request.json → detected as Json read (attribute access).

        Fixture: flask_basic/app.py::input_json_attr()
        EXPECT: one Json read, access_pattern=ATTRIBUTE
        """
        routes = _routes_by_endpoint(flask_basic)
        route = routes["input_json_attr"]
        reads = list(route.body.reads(Json()))

        assert len(reads) == 1
        assert reads[0].source == Json(path=None)
        assert reads[0].access_pattern is AccessPattern.ATTRIBUTE
        assert reads[0].cardinality is Cardinality.SINGLE

    def test_l0_request_headers(self, flask_basic: RepoView) -> None:
        """request.headers.get("Authorization") → Header read.

        Fixture: flask_basic/app.py::input_headers()
        """
        routes = _routes_by_endpoint(flask_basic)
        route = routes["input_headers"]
        reads = list(route.body.reads(Header()))

        assert len(reads) == 1
        assert reads[0].source == Header(name=Key("Authorization"))
        assert reads[0].access_pattern is AccessPattern.GET
        assert reads[0].cardinality is Cardinality.SINGLE

    def test_l0_request_cookies(self, flask_basic: RepoView) -> None:
        """request.cookies.get("session_token") → Cookie read.

        Fixture: flask_basic/app.py::input_cookies()
        """
        routes = _routes_by_endpoint(flask_basic)
        route = routes["input_cookies"]
        reads = list(route.body.reads(Cookie()))

        assert len(reads) == 1
        assert reads[0].source == Cookie(name=Key("session_token"))
        assert reads[0].access_pattern is AccessPattern.GET
        assert reads[0].cardinality is Cardinality.SINGLE

    def test_l0_request_files(self, flask_basic: RepoView) -> None:
        """request.files["document"] → FileUpload read.

        Fixture: flask_basic/app.py::input_files()
        """
        routes = _routes_by_endpoint(flask_basic)
        route = routes["input_files"]
        reads = list(route.body.reads(FileUpload()))

        assert len(reads) == 1
        assert reads[0].source == FileUpload(field=Key("document"))
        assert reads[0].access_pattern is AccessPattern.SUBSCRIPT
        assert reads[0].cardinality is Cardinality.SINGLE

    def test_l0_request_data(self, flask_basic: RepoView) -> None:
        """request.data → RawBody read.

        Fixture: flask_basic/app.py::input_raw()
        """
        routes = _routes_by_endpoint(flask_basic)
        route = routes["input_raw"]
        reads = list(route.body.reads(RawBody()))

        assert len(reads) == 1
        assert isinstance(reads[0].source, RawBody)
        assert reads[0].access_pattern is AccessPattern.ATTRIBUTE
        assert reads[0].cardinality is Cardinality.SINGLE

    def test_l0_path_param(self, flask_basic: RepoView) -> None:
        """Route parameter <int:item_id> → PathParam read.

        Fixture: flask_basic/app.py::input_path()
        EXPECT: PathParam read with key=Key("item_id")
        """
        routes = _routes_by_endpoint(flask_basic)
        route = routes["input_path"]
        reads = list(route.body.reads(PathParam()))

        assert len(reads) == 1
        assert reads[0].source == PathParam(name=Key("item_id"))
        assert reads[0].value_type is InputValueType.INTEGER
        assert reads[0].cardinality is Cardinality.SINGLE

    # -- L1: Import aliasing ---------------------------------------------

    def test_l1_aliased_request_args(self, flask_aliased: RepoView) -> None:
        """from flask import request as req; req.args.get("user_id").

        Fixture: flask_aliased/app.py::input_query()
        EXPECT: same Query read as L0 — alias resolves to flask.request
        """
        routes = _routes_by_endpoint(flask_aliased)
        route = routes["input_query"]
        reads = list(route.body.reads(Query()))

        assert len(reads) == 1
        assert reads[0].source == Query(key=Key("user_id"))
        assert reads[0].access_pattern is AccessPattern.GET
        assert reads[0].cardinality is Cardinality.SINGLE

    def test_l1_aliased_request_form(self, flask_aliased: RepoView) -> None:
        """req.form["name"] — aliased request, still Form read.

        Fixture: flask_aliased/app.py::input_form()
        """
        routes = _routes_by_endpoint(flask_aliased)
        route = routes["input_form"]
        reads = list(route.body.reads(Form()))

        assert len(reads) == 1
        assert reads[0].source == Form(key=Key("name"))
        assert reads[0].access_pattern is AccessPattern.SUBSCRIPT

    def test_l1_aliased_request_json(self, flask_aliased: RepoView) -> None:
        """req.json — aliased request, still Json read.

        Fixture: flask_aliased/app.py::input_json()
        """
        routes = _routes_by_endpoint(flask_aliased)
        route = routes["input_json"]
        reads = list(route.body.reads(Json()))

        assert len(reads) == 1
        assert reads[0].source == Json(path=None)
        assert reads[0].access_pattern is AccessPattern.ATTRIBUTE

    def test_l1_aliased_request_headers(self, flask_aliased: RepoView) -> None:
        """req.headers — aliased request, still Header read.

        Fixture: flask_aliased/app.py::input_headers()
        """
        routes = _routes_by_endpoint(flask_aliased)
        route = routes["input_headers"]
        reads = list(route.body.reads(Header()))

        assert len(reads) == 1
        assert reads[0].source == Header(name=Key("Authorization"))
        assert reads[0].access_pattern is AccessPattern.GET

    def test_l1_aliased_request_cookies(self, flask_aliased: RepoView) -> None:
        """req.cookies — aliased request, still Cookie read.

        Fixture: flask_aliased/app.py::input_cookies()
        """
        routes = _routes_by_endpoint(flask_aliased)
        route = routes["input_cookies"]
        reads = list(route.body.reads(Cookie()))

        assert len(reads) == 1
        assert reads[0].source == Cookie(name=Key("session_token"))
        assert reads[0].access_pattern is AccessPattern.GET

    # -- L2: Variable assignment -----------------------------------------

    def test_l2_request_in_variable(self, flask_indirect: RepoView) -> None:
        """r = request; r.args.get("user_id") → still Query read.

        Fixture: flask_indirect/app.py::l2_variable_assignment()
        EXPECT: L1 value-flow resolves r → request, then attribute match
        """
        routes = _routes_by_endpoint(flask_indirect)
        route = routes["l2_variable_assignment"]
        reads = list(route.body.reads(Query()))

        assert len(reads) == 1
        assert reads[0].source == Query(key=Key("user_id"))
        assert reads[0].access_pattern is AccessPattern.GET
        assert reads[0].cardinality is Cardinality.SINGLE

    # -- L3: Cross-function same-file ------------------------------------

    def test_l3_input_in_helper(self, flask_indirect: RepoView) -> None:
        """_get_user_id() reads request.args → detected in route scope.

        Fixture: flask_indirect/app.py::l3_cross_function_input()
        EXPECT: Query read detected via call-graph inclusion of _get_user_id
        """
        routes = _routes_by_endpoint(flask_indirect)
        route = routes["l3_cross_function_input"]
        reads = list(route.body.reads(Query()))

        assert len(reads) == 1
        assert reads[0].source == Query(key=Key("user_id"))
        assert reads[0].access_pattern is AccessPattern.GET

    # -- L4: Cross-file import -------------------------------------------

    def test_l4_input_in_imported_module(self, flask_indirect: RepoView) -> None:
        """helpers.get_query_param("search") reads request.args.

        Fixture: flask_indirect/app.py::l4_cross_file_input()
        EXPECT: Query read detected via cross-file call-graph
        """
        routes = _routes_by_endpoint(flask_indirect)
        route = routes["l4_cross_file_input"]
        reads = list(route.body.reads(Query()))

        # Cross-file resolution detects the read but key is None
        # because the parameter name is a variable
        assert len(reads) == 1
        assert isinstance(reads[0].source, Query)
        assert reads[0].access_pattern is AccessPattern.GET

    # -- L6: Multi-level indirection -------------------------------------

    def test_l6_chained_variable_access(self, flask_indirect: RepoView) -> None:
        """x = request; a = x.args; v = a.get("key") → Query read.

        Fixture: flask_indirect/app.py::l6_chained_indirection()
        EXPECT: 3-step chain resolves to Query read with key=Key("key")
        """
        routes = _routes_by_endpoint(flask_indirect)
        route = routes["l6_chained_indirection"]
        reads = list(route.body.reads(Query()))

        assert len(reads) == 1
        assert reads[0].source == Query(key=Key("key"))
        assert reads[0].access_pattern is AccessPattern.GET

    def test_l6_nested_cross_file_call(self, flask_indirect: RepoView) -> None:
        """utils.process_input() → helpers.get_query_param() → request.args.

        Fixture: flask_indirect/app.py::l6_nested_call()
        EXPECT: Two-hop cross-file chain resolves to Query read
        """
        routes = _routes_by_endpoint(flask_indirect)
        route = routes["l6_nested_call"]
        reads = list(route.body.reads(Query()))

        # Two-hop cross-file chain detected, key is None (dynamic param)
        assert len(reads) == 1
        assert isinstance(reads[0].source, Query)
        assert reads[0].access_pattern is AccessPattern.GET

    # -- L7: Dynamic (expected to NOT detect) ----------------------------

    def test_l7_getattr_not_detected(self, flask_indirect: RepoView) -> None:
        """getattr(request, 'args') → NOT detected as input.

        Fixture: flask_indirect/app.py::l7_getattr()
        EXPECT: no input reads detected (dynamic attribute access)
        """
        routes = _routes_by_endpoint(flask_indirect)
        route = routes["l7_getattr"]
        reads = list(route.body.reads())

        assert len(reads) == 0

    def test_l7_dict_dispatch_not_detected(self, flask_indirect: RepoView) -> None:
        """sources = {"q": request.args, ...} → NOT fully resolvable.

        Fixture: flask_indirect/app.py::l7_dict_dispatch()
        EXPECT: request.args and request.form accesses in the dict
                literal MAY be detected (they're direct attribute
                accesses), but the dict lookup dispatch is not.
        """
        routes = _routes_by_endpoint(flask_indirect)
        route = routes["l7_dict_dispatch"]
        reads = list(route.body.reads())

        # The raw attribute accesses (request.args, request.form) in the
        # dict literal ARE detected as bare attribute reads, even though
        # the dict-based dispatch is not resolved.
        assert len(reads) >= 1
        source_types = {type(r.source) for r in reads}
        # At least one of Query or Form detected from the dict literal
        assert source_types & {Query, Form}


# =====================================================================
# InputMethodPattern — request.get_json(), etc.
# =====================================================================


class TestInputMethodPattern:
    """Test detection of method-call input patterns.

    Provider declaration:
        InputMethodPattern(
            fqn="flask.wrappers.Request.get_json",
            source_type="Json",
        )
    """

    def test_l0_get_json_direct(self, flask_basic: RepoView) -> None:
        """request.get_json() → Json read.

        Fixture: flask_basic/app.py::input_json_method()
        EXPECT: Json read, access_pattern=ATTRIBUTE
        """
        routes = _routes_by_endpoint(flask_basic)
        route = routes["input_json_method"]
        reads = list(route.body.reads(Json()))

        assert len(reads) == 1
        assert reads[0].source == Json(path=None)
        assert reads[0].access_pattern is AccessPattern.ATTRIBUTE
        assert reads[0].cardinality is Cardinality.SINGLE

    def test_l1_aliased_get_json(self, flask_aliased: RepoView) -> None:
        """req.get_json() where req is aliased request → still Json read."""
        routes = _routes_by_endpoint(flask_aliased)
        route = routes["input_json"]
        reads = list(route.body.reads(Json()))

        assert len(reads) == 1
        assert reads[0].source == Json(path=None)
        assert reads[0].access_pattern is AccessPattern.ATTRIBUTE

    @pytest.mark.xfail(
        reason=(
            "P6.1b [blocked-on: L1-H04/L1-H05]: cross-file input "
            "propagation requires type enrichment"
        ),
        strict=False,
    )
    def test_l4_cross_file_get_json(self, flask_indirect: RepoView) -> None:
        """helpers.get_json_field() calls request.get_json() → detected.

        Fixture: flask_indirect/helpers.py::get_json_field()
        """
        all_reads: list[InputRead] = []
        for route in flask_indirect.routes:
            all_reads.extend(route.body.reads(Json()))
        assert len(all_reads) > 0


# =====================================================================
# InputFieldAccessPattern — form.field.data
# =====================================================================


class TestInputFieldAccessPattern:
    """Test detection of form field attribute input patterns.

    Provider declaration:
        InputFieldAccessPattern(
            base_class_fqn="flask_wtf.FlaskForm",
            field_attribute="data",
            source_type="Form",
        )
    """

    def test_l0_direct_field_access(self, flask_subclassed: RepoView) -> None:
        """form.username.data on FlaskForm subclass → Form read.

        Fixture: flask_subclassed/app.py::register()
        EXPECT: Form reads for username, email, password fields
        """
        routes = _routes_by_endpoint(flask_subclassed)
        route = routes["register"]
        reads = list(route.body.reads(Form()))

        assert len(reads) >= 3
        keys = {cast("Form", r.source).key for r in reads}
        assert "username" in keys
        assert "email" in keys
        assert "password" in keys

    def test_l5_subclass_field_access(self, flask_subclassed: RepoView) -> None:
        """RegistrationForm(FlaskForm).username.data → Form read.

        The engine must:
        1. Detect RegistrationForm as FlaskForm subclass (MRO)
        2. Apply InputFieldAccessPattern to .data accesses
        3. Report source_type="Form" for each field

        Fixture: flask_subclassed/app.py::register()
        EXPECT: 3 Form reads (username, email, password)
        """
        routes = _routes_by_endpoint(flask_subclassed)
        route = routes["register"]
        reads = list(route.body.reads(Form()))

        assert len(reads) >= 3
        keys = {cast("Form", r.source).key for r in reads}
        assert "username" in keys
        assert "email" in keys
        assert "password" in keys
        assert all(r.access_pattern is AccessPattern.ATTRIBUTE for r in reads)


# =====================================================================
# InputParameterPattern — FastAPI Query(), Body(), etc.
# =====================================================================


class TestInputParameterPattern:
    """Test detection of parameter-annotation input patterns.

    Provider declaration:
        InputParameterPattern(
            default_type_fqn="fastapi.Query",
            source_type="Query",
            key_from="param_name",
        )
    """

    def test_l0_query_parameter(self, fastapi_basic: RepoView) -> None:
        """q: str = Query(None) → Query input with key=Key("q").

        Fixture: fastapi_basic/app.py::search()
        EXPECT: 3 Query reads (q, limit, offset)
        """
        routes = _routes_by_endpoint(fastapi_basic)
        route = routes["search"]
        reads = list(route.body.reads(Query()))

        assert len(reads) == 3
        keys = {cast("Query", r.source).key for r in reads}
        assert keys == {"q", "limit", "offset"}

    def test_l0_header_parameter(self, fastapi_basic: RepoView) -> None:
        """x_token: str = Header(...) → Header input with key=Key("x_token").

        Fixture: fastapi_basic/app.py::with_header()
        EXPECT: 2 Header reads (x_token, x_api_key)
        """
        routes = _routes_by_endpoint(fastapi_basic)
        route = routes["with_header"]
        reads = list(route.body.reads(Header()))

        assert len(reads) == 2
        names = {cast("Header", r.source).name for r in reads}
        assert names == {"x_token", "x_api_key"}

    def test_l0_cookie_parameter(self, fastapi_basic: RepoView) -> None:
        """session_id: str = Cookie(None) → Cookie input.

        Fixture: fastapi_basic/app.py::with_cookie()
        EXPECT: 1 Cookie read (session_id)
        """
        routes = _routes_by_endpoint(fastapi_basic)
        route = routes["with_cookie"]
        reads = list(route.body.reads(Cookie()))

        assert len(reads) == 1
        assert reads[0].source == Cookie(name=Key("session_id"))

    def test_l0_path_parameter(self, fastapi_basic: RepoView) -> None:
        """item_id: int in path → PathParam input.

        Fixture: fastapi_basic/app.py::get_item()
        EXPECT: 1 PathParam read (item_id)
        """
        routes = _routes_by_endpoint(fastapi_basic)
        route = routes["get_item"]
        reads = list(route.body.reads(PathParam()))

        assert len(reads) == 1
        assert reads[0].source == PathParam(name=Key("item_id"))

    def test_l0_explicit_path_parameter(self, fastapi_basic: RepoView) -> None:
        """item_id: int = Path(...) → PathParam input via parameter marker."""
        routes = _routes_by_endpoint(fastapi_basic)
        route = routes["get_explicit_item"]
        reads = list(route.body.reads(PathParam()))

        assert len(reads) == 1
        assert reads[0].source == PathParam(name=Key("item_id"))

    def test_l0_body_parameter(self, fastapi_basic: RepoView) -> None:
        """name: str = Body(...) → Json input via parameter marker."""
        routes = _routes_by_endpoint(fastapi_basic)
        route = routes["create_from_body"]
        reads = list(route.body.reads(Json()))

        assert len(reads) == 2
        paths = {cast("Json", read.source).path for read in reads}
        assert paths == {"$.name", "$.quantity"}

    def test_l0_form_parameter(self, fastapi_basic: RepoView) -> None:
        """username: str = Form(...) → Form input via parameter marker."""
        routes = _routes_by_endpoint(fastapi_basic)
        route = routes["submit_form"]
        reads = list(route.body.reads(Form()))

        assert len(reads) == 2
        keys = {cast("Form", read.source).key for read in reads}
        assert keys == {"username", "csrf_token"}

    def test_l0_file_parameter(self, fastapi_basic: RepoView) -> None:
        """avatar: UploadFile = File(...) → FileUpload input via parameter marker."""
        routes = _routes_by_endpoint(fastapi_basic)
        route = routes["upload_avatar"]
        reads = list(route.body.reads(FileUpload()))

        assert len(reads) == 1
        assert reads[0].source == FileUpload(field=Key("avatar"))


# =====================================================================
# Django input patterns (request.GET, request.POST)
# =====================================================================


class TestDjangoInputPatterns:
    """Test input detection on Django's HttpRequest.

    Provider declaration:
        InputAttributePattern(
            receiver_fqn="django.http.request.HttpRequest",
            attribute="GET",
            source_type="Query",
        )
    """

    @pytest.mark.xfail(
        reason=(
            "P9.1a [blocked-on: L1-H04/L1-H05]: Django request.GET.get() "
            "requires type enrichment to resolve HttpRequest attribute FQNs"
        ),
        strict=False,
    )
    def test_l0_request_get(self, django_basic: RepoView) -> None:
        """request.GET.get("page") → Query read.

        Fixture: django_basic/views.py::user_list()
        EXPECT: Query read with key=Key("page")
        """
        routes = _routes_by_endpoint(django_basic)
        route = routes["user_list"]
        reads = list(route.body.reads(Query()))

        assert len(reads) == 1
        assert reads[0].source == Query(key=Key("page"))

    @pytest.mark.xfail(
        reason=(
            "P9.1a [blocked-on: L1-H04/L1-H05]: Django request.POST['name'] "
            "requires type enrichment to resolve HttpRequest attribute FQNs"
        ),
        strict=False,
    )
    def test_l0_request_post(self, django_basic: RepoView) -> None:
        """request.POST["name"] → Form read.

        Fixture: django_basic/views.py::user_create()
        EXPECT: Form reads for name, email
        """
        routes = _routes_by_endpoint(django_basic)
        route = routes["user_create"]
        reads = list(route.body.reads(Form()))

        assert len(reads) == 2
        keys = {cast("Form", r.source).key for r in reads}
        assert keys == {"name", "email"}


# =====================================================================
# Comprehensive: one test per InputSource subclass
# =====================================================================


class TestInputSourceCompleteness:
    """Ensure every InputSource subclass has at least one detection test.

    These tests confirm that provider declarations for ALL input source
    types result in actual detections on the fixture code.
    """

    def test_query_source(self, flask_basic: RepoView) -> None:
        """At least one Query read detected."""
        all_reads: list[InputRead] = []
        for route in flask_basic.routes:
            all_reads.extend(route.body.reads(Query()))
        assert len(all_reads) >= 1

    def test_form_source(self, flask_basic: RepoView) -> None:
        """At least one Form read detected."""
        all_reads: list[InputRead] = []
        for route in flask_basic.routes:
            all_reads.extend(route.body.reads(Form()))
        assert len(all_reads) >= 1

    def test_json_source(self, flask_basic: RepoView) -> None:
        """At least one Json read detected."""
        all_reads: list[InputRead] = []
        for route in flask_basic.routes:
            all_reads.extend(route.body.reads(Json()))
        assert len(all_reads) >= 1

    def test_header_source(self, flask_basic: RepoView) -> None:
        """At least one Header read detected."""
        all_reads: list[InputRead] = []
        for route in flask_basic.routes:
            all_reads.extend(route.body.reads(Header()))
        assert len(all_reads) >= 1

    def test_cookie_source(self, flask_basic: RepoView) -> None:
        """At least one Cookie read detected."""
        all_reads: list[InputRead] = []
        for route in flask_basic.routes:
            all_reads.extend(route.body.reads(Cookie()))
        assert len(all_reads) >= 1

    def test_path_param_source(self, flask_basic: RepoView) -> None:
        """At least one PathParam read detected."""
        all_reads: list[InputRead] = []
        for route in flask_basic.routes:
            all_reads.extend(route.body.reads(PathParam()))
        assert len(all_reads) >= 1

    def test_file_upload_source(self, flask_basic: RepoView) -> None:
        """At least one FileUpload read detected."""
        all_reads: list[InputRead] = []
        for route in flask_basic.routes:
            all_reads.extend(route.body.reads(FileUpload()))
        assert len(all_reads) >= 1

    def test_raw_body_source(self, flask_basic: RepoView) -> None:
        """At least one RawBody read detected."""
        all_reads: list[InputRead] = []
        for route in flask_basic.routes:
            all_reads.extend(route.body.reads(RawBody()))
        assert len(all_reads) >= 1

    def test_dependency_input_source(self, fastapi_basic: RepoView) -> None:
        """At least one dependency-injected input read detected."""
        all_reads: list[InputRead] = []
        for route in fastapi_basic.routes:
            all_reads.extend(route.body.reads(DependencyInput()))
        assert len(all_reads) >= 1
