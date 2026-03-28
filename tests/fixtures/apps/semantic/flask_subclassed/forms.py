"""WTForms subclasses for InputFieldAccessPattern resolution tests.

The provider declares InputFieldAccessPattern on FlaskForm base.
The engine must detect form.field.data access on subclass instances.
"""

from flask_wtf import FlaskForm


class StringField:
    """Stub mimicking wtforms.StringField."""

    data = ""


class PasswordField:
    """Stub mimicking wtforms.PasswordField."""

    data = ""


class EmailField:
    """Stub mimicking wtforms.EmailField."""

    data = ""


class RegistrationForm(FlaskForm):
    """Subclass of FlaskForm — field.data should be detected as Form input.

    The engine must trace MRO: RegistrationForm → FlaskForm and apply
    the InputFieldAccessPattern to field accesses on RegistrationForm
    instances.
    """

    username = StringField()
    email = EmailField()
    password = PasswordField()
    confirm_password = PasswordField()
