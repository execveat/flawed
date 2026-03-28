"""MethodView subclasses for the factory-registration fixture."""

from flask import jsonify, request
from flask.views import MethodView


class LoginView(MethodView):
    def get(self):
        return jsonify(form="login")

    def post(self):
        return jsonify(status="logged_in")


class LogoutView(MethodView):
    def post(self):
        return jsonify(status="logged_out")


class ProfileView(MethodView):
    def get(self):
        return jsonify(profile="data")
