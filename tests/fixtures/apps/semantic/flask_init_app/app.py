"""Flask extension app exercising init_app lifecycle registrations.

Exercises LifecycleRegistrationPattern declarations for Flask extensions whose
setup call implicitly installs request lifecycle hooks.
"""

from flask import Flask
from flask_login import LoginManager
from flask_wtf import CSRFProtect

app = Flask(__name__)

login_manager = LoginManager()
csrf = CSRFProtect()

login_manager.init_app(app)
csrf.init_app(app)


@app.route("/")
def index():
    """Route used to keep the fixture executable as a web app."""
    return "ok"
