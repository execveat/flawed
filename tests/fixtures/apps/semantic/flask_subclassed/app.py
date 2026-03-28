"""Flask app with subclassing: inherited methods, custom views, form fields.

Level 5 complexity: the Semantic API must resolve inherited methods and
attribute accesses through the class hierarchy.
"""

from flask import Flask, g, jsonify, request

from .forms import RegistrationForm
from .models import Product, User
from .views import ItemAPI

app = Flask(__name__)

# Register class-based view
app.add_url_rule(
    "/api/items",
    view_func=ItemAPI.as_view("items"),
    methods=["GET", "POST"],
)
app.add_url_rule(
    "/api/items/<int:item_id>",
    view_func=ItemAPI.as_view("item_detail"),
    methods=["GET", "PUT", "DELETE"],
)


# -- Subclass method effects (Level 5) --


@app.route("/sub/create_user", methods=["POST"])
def create_user():
    """User().save() should be detected as DB_WRITE.

    User inherits save() from Model (sqlalchemy pattern).
    The provider declares Model.save() as DB_WRITE.
    The engine must trace the MRO: User → Model → save().
    """
    name = request.form["name"]
    user = User(name=name)
    user.save()
    return jsonify({"created": True})


@app.route("/sub/delete_user/<int:user_id>", methods=["DELETE"])
def delete_user(user_id):
    """User().delete() should be detected as DB_DELETE.

    Same MRO tracing as save().
    """
    user = User.get_by_id(user_id)
    if user:
        user.delete()
    return jsonify({"deleted": True})


@app.route("/sub/create_product", methods=["POST"])
def create_product():
    """Product().save() — different Model subclass, same pattern."""
    name = request.form["name"]
    price = request.form.get("price", "0")
    product = Product(name=name, price=float(price))
    product.save()
    return jsonify({"created": True})


# -- Form subclass inputs (Level 5) --


@app.route("/sub/register", methods=["POST"])
def register():
    """RegistrationForm().username.data — subclass field access.

    RegistrationForm extends FlaskForm.  The provider declares
    InputFieldAccessPattern on FlaskForm base.  The engine must
    detect field.data access on the subclass.
    """
    form = RegistrationForm()
    if form.validate_on_submit():
        name = form.username.data
        email = form.email.data
        pw = form.password.data
        return jsonify({"name": name, "email": email})
    return jsonify({"errors": "validation failed"}), 400
