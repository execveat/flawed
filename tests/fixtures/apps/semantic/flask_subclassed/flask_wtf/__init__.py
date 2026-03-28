"""Stub mimicking the flask_wtf package for fixture resolution.

L1 indexes this as module ``flask_wtf``, so ``FlaskForm`` gets FQN
``flask_wtf.FlaskForm`` — matching the provider's
``InputFieldAccessPattern(base_class_fqn="flask_wtf.FlaskForm", ...)``.
"""


class FlaskForm:
    """Stub mimicking flask_wtf.FlaskForm."""

    def validate_on_submit(self) -> bool:
        """Stub: returns True if form is submitted and valid."""
        return True
