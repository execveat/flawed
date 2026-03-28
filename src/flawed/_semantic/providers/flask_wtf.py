"""Flask-WTF provider -- CSRF protection, form handling, file validation.

Covers:
- ``CSRFProtect.init_app`` lifecycle hook (global before_request CSRF guard)
- ``CSRFProtect.exempt`` config write (disables CSRF for a view/blueprint)
- ``CSRFProtect.protect`` explicit CSRF validation call
- ``FlaskForm.validate_on_submit`` combined CSRF + field validation check
- ``generate_csrf`` / ``validate_csrf`` standalone CSRF functions
- Form field data access via ``form.<field>.data``
- File upload validators: ``FileRequired``, ``FileAllowed``, ``FileSize``
- reCAPTCHA field as security check

FQNs verified against Flask-WTF 1.3.0 and WTForms 3.2.2 source.
"""

from __future__ import annotations

from flawed._semantic.providers._base import (
    CheckKind,
    ControlPlaneExemptionPattern,
    EffectCallPattern,
    HookType,
    InputFieldAccessPattern,
    InputMethodPattern,
    LifecycleRegistrationPattern,
    Provider,
    ProviderMeta,
    SecurityCheckPattern,
    arg,
)


class FlaskWtfProvider(Provider):
    meta = ProviderMeta(
        id="flask-wtf",
        name="Flask-WTF",
        version="0.1.0",
        library="Flask-WTF",
        library_fqn="flask_wtf",
    )

    # =================================================================
    # Security checks
    # =================================================================

    checks = (
        # -- Form validation (includes CSRF) --
        SecurityCheckPattern(
            fqn="flask_wtf.FlaskForm.validate_on_submit",
            kind=CheckKind.METHOD_CALL,
            category="CSRF|FORM_VALIDATION",
            description="Form submitted + all validators pass (includes CSRF)",
        ),
        SecurityCheckPattern(
            fqn="flask_wtf.form.FlaskForm.validate_on_submit",
            kind=CheckKind.METHOD_CALL,
            category="CSRF|FORM_VALIDATION",
            description="Form validation (internal import path)",
        ),
        # -- Explicit CSRF validation --
        SecurityCheckPattern(
            fqn="flask_wtf.csrf.CSRFProtect.protect",
            kind=CheckKind.METHOD_CALL,
            category="CSRF",
            description="Explicit CSRF validation call",
        ),
        SecurityCheckPattern(
            fqn="flask_wtf.csrf.validate_csrf",
            kind=CheckKind.CALL,
            category="CSRF",
            description="Standalone CSRF token validation function",
        ),
        # -- WTForms Form.validate (base validation without submit check) --
        SecurityCheckPattern(
            fqn="wtforms.form.Form.validate",
            kind=CheckKind.METHOD_CALL,
            category="FORM_VALIDATION",
            description="WTForms field validation (no CSRF without FlaskForm)",
        ),
        # -- File upload validators as security checks --
        SecurityCheckPattern(
            fqn="flask_wtf.file.FileRequired",
            kind=CheckKind.CALL,
            category="FILE_VALIDATION",
            description="Validates file upload is present (FileStorage check)",
        ),
        SecurityCheckPattern(
            fqn="flask_wtf.file.FileAllowed",
            kind=CheckKind.CALL,
            category="FILE_VALIDATION",
            description="Validates file extension against allowlist",
        ),
        SecurityCheckPattern(
            fqn="flask_wtf.file.FileSize",
            kind=CheckKind.CALL,
            category="FILE_VALIDATION",
            description="Validates file size within min/max bounds",
        ),
        # -- reCAPTCHA field --
        SecurityCheckPattern(
            fqn="flask_wtf.recaptcha.validators.Recaptcha",
            kind=CheckKind.CALL,
            category="CAPTCHA",
            description="Google reCAPTCHA validation",
        ),
    )

    # =================================================================
    # Effects: CSRF exemption (CONFIG_WRITE), token generation
    # =================================================================

    effects = (
        EffectCallPattern(
            fqn="flask_wtf.CSRFProtect.exempt",
            category="CONFIG_WRITE",
            scope="SERVER",
            description="Marks view or blueprint as CSRF-exempt (public import path)",
        ),
        EffectCallPattern(
            fqn="flask_wtf.csrf.CSRFProtect.exempt",
            category="CONFIG_WRITE",
            scope="SERVER",
            description="Marks view or blueprint as CSRF-exempt",
        ),
        # CSRF token generation writes to session
        EffectCallPattern(
            fqn="flask_wtf.csrf.generate_csrf",
            category="STATE_WRITE",
            scope="SESSION",
            keys=("csrf_token",),
            description="Generates CSRF token and stores in session",
        ),
    )

    # =================================================================
    # Input sources: form field data access
    # =================================================================

    inputs = (
        # form.data -> dict of all field values (property on BaseForm)
        InputMethodPattern(
            fqn="wtforms.form.BaseForm.data",
            source_type="Form",
            cardinality="MULTI",
            description="Dictionary of all form field values",
        ),
        # form.<field>.data -> individual typed value
        # Matches any FlaskForm subclass field with .data access
        InputFieldAccessPattern(
            base_class_fqn="flask_wtf.FlaskForm",
            field_attribute="data",
            source_type="Form",
            cardinality="SINGLE",
            description="Individual form field value (type-coerced)",
        ),
        InputFieldAccessPattern(
            base_class_fqn="flask_wtf.form.FlaskForm",
            field_attribute="data",
            source_type="Form",
            cardinality="SINGLE",
            description="Individual form field value (internal path)",
        ),
        # FileField.data yields a FileStorage (uploaded file content)
        InputFieldAccessPattern(
            base_class_fqn="flask_wtf.file.FileField",
            field_attribute="data",
            source_type="FileUpload",
            cardinality="SINGLE",
            description="Uploaded file data (werkzeug FileStorage)",
        ),
        InputFieldAccessPattern(
            base_class_fqn="flask_wtf.file.MultipleFileField",
            field_attribute="data",
            source_type="FileUpload",
            cardinality="MULTI",
            description="Multiple uploaded files (list of FileStorage)",
        ),
    )

    # =================================================================
    # Lifecycle hooks
    # =================================================================

    lifecycle = (
        # CSRFProtect.init_app registers a before_request hook that
        # calls self.protect(apply_exemptions=True) on every request
        # with a state-changing method (POST/PUT/PATCH/DELETE).
        LifecycleRegistrationPattern(
            registration_fqn="flask_wtf.csrf.CSRFProtect.init_app",
            hook_type=HookType.BEFORE_HANDLER,
            check_category="CSRF",
            description="Global CSRF validation on POST/PUT/PATCH/DELETE",
        ),
        LifecycleRegistrationPattern(
            registration_fqn="flask_wtf.CSRFProtect.init_app",
            hook_type=HookType.BEFORE_HANDLER,
            check_category="CSRF",
            description="Global CSRF validation (public import path)",
        ),
        # The CSRFProtect(app) CONSTRUCTOR is equivalent to init_app: flask-wtf's
        # ``CSRFProtect.__init__`` calls ``self.init_app(app)`` when an app is
        # passed (csrf.py in Flask-WTF 1.x).  Real apps use this one-liner form
        # (e.g. ``csrf = CSRFProtect(app)``) far more than the deferred
        # ``CSRFProtect(); init_app(app)`` split, so the engine must treat the
        # constructor as the same global before_request CSRF registration -- not
        # doing so left every state-changing route looking unprotected (FLAW-128,
        # ~121 false positives on one real-world corpus).
        #
        # The ``when=arg(0)...`` predicate is load-bearing: ONLY the constructor
        # that receives an app registers CSRF.  A bare ``CSRFProtect()`` (the
        # deferred form, or an unbound handle used purely for ``csrf.exempt(...)``)
        # must NOT mark routes as covered -- doing so is a fail-open that hides
        # missing auth/CSRF (it regressed an auth-coverage rule, which treats any check as
        # coverage).  ``type_is`` returns FAILED when arg 0 is absent (bare form,
        # correctly skipped) and PASSED/UNKNOWN when present (the matcher treats
        # UNKNOWN as non-failing, so a real ``CSRFProtect(app)`` still matches even
        # when type enrichment can't pin ``app`` to ``flask.Flask``).  The deferred
        # ``CSRFProtect(); init_app(app)`` form stays covered by the init_app
        # patterns above.
        LifecycleRegistrationPattern(
            registration_fqn="flask_wtf.csrf.CSRFProtect",
            hook_type=HookType.BEFORE_HANDLER,
            check_category="CSRF",
            when=arg(0).type_is("flask.Flask"),
            description="CSRFProtect(app) constructor registers global CSRF (calls init_app)",
        ),
        LifecycleRegistrationPattern(
            registration_fqn="flask_wtf.CSRFProtect",
            hook_type=HookType.BEFORE_HANDLER,
            check_category="CSRF",
            when=arg(0).type_is("flask.Flask"),
            description="CSRFProtect(app) constructor registers global CSRF (public import path)",
        ),
        # Call-form CSRF exemption: ``csrf.exempt(view)`` / ``csrf.exempt(bp)``
        # at module scope.  The decorator form (``@csrf.exempt``) is captured on
        # the view and surfaces via ``route.body.decorators()``; the call form is
        # a bare module statement with no enclosing function, so the
        # EffectCallPattern below drops it (no caller function).  This pattern
        # re-attributes the CONFIG_WRITE exemption onto the named view's route
        # (or every route under the named blueprint), so effect-based CSRF
        # consumers recognise it (FLAW-181).
        ControlPlaneExemptionPattern(
            registration_fqn=(
                "flask_wtf.CSRFProtect.exempt",
                "flask_wtf.csrf.CSRFProtect.exempt",
            ),
            category="CONFIG_WRITE",
            scope="SERVER",
            target_arg=0,
            description="csrf.exempt(view|blueprint) call-form CSRF exemption",
        ),
    )
