"""Flask-RESTX semantic fixture — package-root import idiom.

Real flask-restx apps (e.g. a large API surface under ``api/v1``) import the
public names from the *package root* — ``from flask_restx import Api, Namespace,
Resource`` — even though those classes are *defined* in submodules
(``flask_restx.namespace.Namespace``, ``flask_restx.resource.Resource``).

The engine resolves a symbol to the FQN of the import path the app used, so the
provider must declare the root-reexport spellings alongside the submodule ones
(mirroring how ``flask_core`` declares both ``flask.Flask.route`` and
``flask.Blueprint.route``). Without the root aliases the ``@ns.route`` decorator
and the ``Resource`` base class both fail to match and the whole API is invisible
— a corpus-wide false negative. This fixture pins that idiom.
"""

from flask_restx import Api, Namespace, Resource

api = Api()
ns = Namespace("users", description="User operations")


@ns.route("/users/<int:user_id>")
class UserResource(Resource):
    def get(self, user_id):
        return {"id": user_id}

    def delete(self, user_id):
        return None


class ItemResource(Resource):
    def get(self, item_id):
        return {"id": item_id}


# Imperative registration form: ns.add_resource(Resource, "/path")
ns.add_resource(ItemResource, "/items/<int:item_id>")
