"""Unit coverage for custom astroid brain plugins."""

from __future__ import annotations

from typing import TYPE_CHECKING

import astroid
from astroid import nodes

import flawed._index._brains as custom_brains

if TYPE_CHECKING:
    from collections.abc import Iterable


def _assignment_value(module: nodes.Module, name: str) -> nodes.NodeNG:
    for statement in module.body:
        if not isinstance(statement, nodes.Assign):
            continue
        for target in statement.targets:
            if isinstance(target, nodes.AssignName) and target.name == name:
                return statement.value
    raise AssertionError(f"assignment {name!r} not found")


def _inferred(module: nodes.Module, name: str) -> tuple[object, ...]:
    return tuple(_assignment_value(module, name).infer())


def _pytypes(results: Iterable[object]) -> set[str]:
    return {result.pytype() for result in results if hasattr(result, "pytype")}


def _names(results: Iterable[object]) -> set[str]:
    return {result.name for result in results if hasattr(result, "name")}


def _registration_counts() -> tuple[int, int, int, int]:
    manager = astroid.MANAGER
    transforms = manager._transform.transforms
    return (
        len(manager._failed_import_hooks),
        len(transforms[nodes.Module]),
        len(transforms[nodes.ClassDef]),
        len(transforms[nodes.Call]),
    )


class TestFlaskBrain:
    def test_request_form_resolves(self) -> None:
        module = astroid.parse(
            """
            from flask import request
            form_data = request.form
            """
        )

        results = _inferred(module, "form_data")

        assert astroid.Uninferable not in results
        assert "ImmutableMultiDict" in _names(results)

    def test_request_json_resolves_as_optional_payload(self) -> None:
        module = astroid.parse(
            """
            from flask import request
            json_data = request.json
            """
        )

        results = _inferred(module, "json_data")

        assert astroid.Uninferable not in results
        assert _pytypes(results) == {"builtins.NoneType", "builtins.dict"}

    def test_request_files_headers_method_and_data_resolve(self) -> None:
        module = astroid.parse(
            """
            from flask import request
            uploaded = request.files
            headers = request.headers
            method = request.method
            body = request.data
            """
        )

        assert "ImmutableMultiDict" in _names(_inferred(module, "uploaded"))
        assert "EnvironHeaders" in _names(_inferred(module, "headers"))
        assert _pytypes(_inferred(module, "method")) == {"builtins.str"}
        assert _pytypes(_inferred(module, "body")) == {"builtins.bytes"}

    def test_context_globals_and_session_resolve(self) -> None:
        module = astroid.parse(
            """
            from flask import g, session
            app_globals = g
            user_session = session
            """
        )

        assert "_AppGlobals" in _names(_inferred(module, "app_globals"))
        assert "SecureCookieSession" in _names(_inferred(module, "user_session"))

    def test_route_decorator_preserves_signature(self) -> None:
        module = astroid.parse(
            """
            from flask import Flask
            app = Flask(__name__)

            @app.route("/admin/<int:user_id>")
            def admin_panel(user_id: int) -> str:
                return "ok"

            decorated = admin_panel
            response = admin_panel(1)
            """
        )

        function_results = _inferred(module, "decorated")
        response_results = _inferred(module, "response")

        assert any(
            isinstance(result, nodes.FunctionDef)
            and result.name == "admin_panel"
            and result.args.args[0].name == "user_id"
            for result in function_results
        )
        assert _pytypes(response_results) == {"builtins.str"}

    def test_blueprint_route_decorator_preserves_signature(self) -> None:
        module = astroid.parse(
            """
            from flask import Blueprint
            blueprint = Blueprint("auth", __name__)

            @blueprint.route("/login")
            def login() -> str:
                return "ok"

            decorated = login
            """
        )

        assert any(
            isinstance(result, nodes.FunctionDef) and result.name == "login"
            for result in _inferred(module, "decorated")
        )


class TestBrainRegistration:
    def test_package_register_is_idempotent_for_default_manager(self) -> None:
        before = _registration_counts()

        custom_brains.register()

        assert _registration_counts() == before


class TestSQLAlchemyBrain:
    def test_column_integer_maps_to_int(self) -> None:
        module = astroid.parse(
            """
            from sqlalchemy import Column, Integer

            class User:
                id = Column(Integer)

            user = User()
            value = user.id
            """
        )

        assert _pytypes(_inferred(module, "value")) == {"builtins.int"}

    def test_nullable_column_maps_to_optional(self) -> None:
        module = astroid.parse(
            """
            from sqlalchemy import Column, Integer

            class User:
                age = Column(Integer, nullable=True)

            user = User()
            value = user.age
            """
        )

        assert _pytypes(_inferred(module, "value")) == {
            "builtins.NoneType",
            "builtins.int",
        }

    def test_string_boolean_float_and_datetime_columns_resolve(self) -> None:
        module = astroid.parse(
            """
            from sqlalchemy import Boolean, Column, DateTime, Float, String

            class User:
                name = Column(String(64))
                active = Column(Boolean)
                score = Column(Float)
                created_at = Column(DateTime)

            user = User()
            name = user.name
            active = user.active
            score = user.score
            created_at = user.created_at
            """
        )

        assert _pytypes(_inferred(module, "name")) == {"builtins.str"}
        assert _pytypes(_inferred(module, "active")) == {"builtins.bool"}
        assert _pytypes(_inferred(module, "score")) == {"builtins.float"}
        assert "datetime" in _names(_inferred(module, "created_at"))

    def test_relationship_resolves_target(self) -> None:
        module = astroid.parse(
            """
            from sqlalchemy.orm import relationship

            class User:
                pass

            class Post:
                author = relationship("User", uselist=False)

            post = Post()
            value = post.author
            """
        )

        assert "User" in _names(_inferred(module, "value"))

    def test_relationship_uselist_resolves_list(self) -> None:
        module = astroid.parse(
            """
            from sqlalchemy.orm import relationship

            class User:
                pass

            class Team:
                members = relationship("User", uselist=True)

            team = Team()
            value = team.members
            """
        )

        assert _pytypes(_inferred(module, "value")) == {"builtins.list"}

    def test_query_first_returns_optional_model(self) -> None:
        module = astroid.parse(
            """
            class User:
                pass

            value = session.query(User).filter(True).first()
            """
        )

        assert _pytypes(_inferred(module, "value")) == {
            ".User",
            "builtins.NoneType",
        }

    def test_query_and_filter_return_query_object(self) -> None:
        module = astroid.parse(
            """
            class User:
                pass

            query = session.query(User)
            filtered = session.query(User).filter(True)
            """
        )

        assert "Query" in _names(_inferred(module, "query"))
        assert "Query" in _names(_inferred(module, "filtered"))

    def test_query_all_and_one_return_collection_shapes(self) -> None:
        module = astroid.parse(
            """
            class User:
                pass

            users = session.query(User).all()
            user = session.query(User).one()
            """
        )

        assert _pytypes(_inferred(module, "users")) == {"builtins.list"}
        assert _pytypes(_inferred(module, "user")) == {".User"}


class TestFlaskLoginBrain:
    def test_login_required_preserves_signature(self) -> None:
        module = astroid.parse(
            """
            from flask_login import login_required

            @login_required
            def admin_panel(user_id: int) -> str:
                return "ok"

            decorated = admin_panel
            response = admin_panel(1)
            """
        )

        function_results = _inferred(module, "decorated")

        assert any(
            isinstance(result, nodes.FunctionDef)
            and result.name == "admin_panel"
            and result.args.args[0].name == "user_id"
            for result in function_results
        )
        assert _pytypes(_inferred(module, "response")) == {"builtins.str"}

    def test_current_user_resolves_to_single_local_user_model(self) -> None:
        module = astroid.parse(
            """
            from flask_login import UserMixin, current_user

            class User(UserMixin):
                def __init__(self):
                    self.id = 0

            value = current_user.id
            """
        )

        assert _pytypes(_inferred(module, "value")) == {"builtins.int"}

    def test_login_user_and_logout_user_return_bool(self) -> None:
        module = astroid.parse(
            """
            from flask_login import login_user, logout_user

            logged_in = login_user(object())
            logged_out = logout_user()
            """
        )

        assert _pytypes(_inferred(module, "logged_in")) == {"builtins.bool"}
        assert _pytypes(_inferred(module, "logged_out")) == {"builtins.bool"}


class TestWTFormsBrain:
    def test_field_data_types_resolve(self) -> None:
        module = astroid.parse(
            """
            from flask_wtf import FlaskForm
            from wtforms import BooleanField, FloatField, IntegerField, StringField

            class ProfileForm(FlaskForm):
                name = StringField()
                age = IntegerField()
                active = BooleanField()
                score = FloatField()

            form = ProfileForm()
            name = form.name.data
            age = form.age.data
            active = form.active.data
            score = form.score.data
            """
        )

        assert _pytypes(_inferred(module, "name")) == {"builtins.str"}
        assert _pytypes(_inferred(module, "age")) == {"builtins.int"}
        assert _pytypes(_inferred(module, "active")) == {"builtins.bool"}
        assert _pytypes(_inferred(module, "score")) == {"builtins.float"}

    def test_select_field_coerce_type_resolves(self) -> None:
        module = astroid.parse(
            """
            from flask_wtf import FlaskForm
            from wtforms import SelectField

            class ProfileForm(FlaskForm):
                user_id = SelectField(coerce=int)

            form = ProfileForm()
            value = form.user_id.data
            """
        )

        assert _pytypes(_inferred(module, "value")) == {"builtins.int"}

    def test_form_validate_errors_and_data_resolve(self) -> None:
        module = astroid.parse(
            """
            from flask_wtf import FlaskForm
            from wtforms import StringField

            class ProfileForm(FlaskForm):
                name = StringField()

            form = ProfileForm()
            valid = form.validate()
            errors = form.errors
            data = form.data
            """
        )

        assert _pytypes(_inferred(module, "valid")) == {"builtins.bool"}
        assert _pytypes(_inferred(module, "errors")) == {"builtins.dict"}
        assert _pytypes(_inferred(module, "data")) == {"builtins.dict"}


class TestFlaskRestfulBrain:
    def test_resource_http_methods_resolve(self) -> None:
        module = astroid.parse(
            """
            from flask_restful import Resource

            class UserResource(Resource):
                def get(self):
                    return {"name": "Alice"}

                def post(self):
                    return {"created": True}

            resource = UserResource()
            get_result = resource.get()
            post_result = resource.post()
            """
        )

        assert _pytypes(_inferred(module, "get_result")) == {"builtins.dict"}
        assert _pytypes(_inferred(module, "post_result")) == {"builtins.dict"}

    def test_api_add_resource_resolves(self) -> None:
        module = astroid.parse(
            """
            from flask_restful import Api

            api = Api()
            result = api.add_resource(object, "/users")
            """
        )

        assert _pytypes(_inferred(module, "result")) == {"builtins.NoneType"}

    def test_request_parser_parse_args_returns_dict(self) -> None:
        module = astroid.parse(
            """
            from flask_restful import RequestParser

            parser = RequestParser()
            parser.add_argument("name")
            args = parser.parse_args()
            """
        )

        assert _pytypes(_inferred(module, "args")) == {"builtins.dict"}

    def test_marshal_returns_dict(self) -> None:
        module = astroid.parse(
            """
            from flask_restful import marshal

            result = marshal({"name": "Alice"}, {})
            """
        )

        assert _pytypes(_inferred(module, "result")) == {"builtins.dict"}

    def test_resource_decorator_preserves_signature(self) -> None:
        module = astroid.parse(
            """
            from flask_restful import Api

            api = Api()

            @api.resource("/users")
            class UserResource:
                def get(self) -> dict:
                    return {}

            decorated = UserResource
            """
        )

        assert any(
            isinstance(result, nodes.ClassDef) and result.name == "UserResource"
            for result in _inferred(module, "decorated")
        )


class TestFlaskRestxBrain:
    def test_namespace_route_preserves_class(self) -> None:
        module = astroid.parse(
            """
            from flask_restx import Namespace, Resource

            ns = Namespace("users")

            @ns.route("/")
            class UserList(Resource):
                def get(self):
                    return []

            decorated = UserList
            """
        )

        assert any(
            isinstance(result, nodes.ClassDef) and result.name == "UserList"
            for result in _inferred(module, "decorated")
        )

    def test_namespace_expect_preserves_function(self) -> None:
        module = astroid.parse(
            """
            from flask_restx import Namespace

            ns = Namespace("users")

            @ns.expect({})
            def create_user():
                return True

            decorated = create_user
            result = create_user()
            """
        )

        assert any(
            isinstance(result, nodes.FunctionDef) and result.name == "create_user"
            for result in _inferred(module, "decorated")
        )
        assert _pytypes(_inferred(module, "result")) == {"builtins.bool"}

    def test_resource_http_methods_resolve(self) -> None:
        module = astroid.parse(
            """
            from flask_restx import Resource

            class ItemResource(Resource):
                def get(self, item_id):
                    return {"id": item_id}

                def delete(self, item_id):
                    return None

            resource = ItemResource()
            get_result = resource.get(1)
            delete_result = resource.delete(1)
            """
        )

        assert _pytypes(_inferred(module, "get_result")) == {"builtins.dict"}
        assert _pytypes(_inferred(module, "delete_result")) == {"builtins.NoneType"}

    def test_request_parser_parse_args_returns_dict(self) -> None:
        module = astroid.parse(
            """
            from flask_restx.reqparse import RequestParser

            parser = RequestParser()
            parser.add_argument("name")
            args = parser.parse_args()
            """
        )

        assert _pytypes(_inferred(module, "args")) == {"builtins.dict"}

    def test_marshal_returns_dict(self) -> None:
        module = astroid.parse(
            """
            from flask_restx.marshalling import marshal

            result = marshal({"name": "Alice"}, {})
            """
        )

        assert _pytypes(_inferred(module, "result")) == {"builtins.dict"}
