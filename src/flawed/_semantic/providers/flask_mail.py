"""Flask-Mail provider -- email notification effects.

Covers:
- ``Mail.send(msg)`` / ``Mail.send_message(...)`` — NOTIFICATION effect
- ``Connection.send(msg)`` / ``Connection.send_message(...)`` — direct send
- ``Mail.connect()`` — OUTBOUND_REQUEST (opens SMTP connection)
- ``Mail(app)`` / ``Mail.init_app(app)`` — lifecycle registration

FQNs verified against Flask-Mail 0.10.x source.  All classes live
directly in ``flask_mail.__init__``.

Note: ``Message`` constructor and ``Message.attach`` are data-building
operations without side effects; the NOTIFICATION effect occurs at
``send()`` time.
"""

from __future__ import annotations

from flawed._semantic.providers._base import (
    EffectCallPattern,
    FlowPropagatorPattern,
    HookType,
    LifecycleRegistrationPattern,
    Provider,
    ProviderMeta,
    TaintSinkPattern,
    kwarg,
)


class FlaskMailProvider(Provider):
    meta = ProviderMeta(
        id="flask-mail",
        name="Flask-Mail",
        version="0.1.0",
        library="Flask-Mail",
        library_fqn="flask_mail",
    )

    # =================================================================
    # Effects: email sending (NOTIFICATION)
    # =================================================================

    effects = (
        # Mail.send(msg) — the primary send method
        EffectCallPattern(
            fqn="flask_mail.Mail.send",
            category="NOTIFICATION",
            description="Sends an email message via SMTP",
        ),
        # Mail.send_message(*args, **kwargs) — shorthand for send(Message(...))
        EffectCallPattern(
            fqn="flask_mail.Mail.send_message",
            category="NOTIFICATION",
            description="Constructs and sends an email in one call",
        ),
        # Connection.send(msg) — send via explicit connection context
        EffectCallPattern(
            fqn="flask_mail.Connection.send",
            category="NOTIFICATION",
            description="Sends email via explicit SMTP connection",
        ),
        # Connection.send_message — shorthand on connection
        EffectCallPattern(
            fqn="flask_mail.Connection.send_message",
            category="NOTIFICATION",
            description="Constructs and sends email via connection",
        ),
        # Mail.connect() — opens SMTP connection
        EffectCallPattern(
            fqn="flask_mail.Mail.connect",
            category="OUTBOUND_REQUEST",
            description="Opens SMTP connection to mail server",
        ),
    )

    # =================================================================
    # Flow propagation
    # =================================================================

    propagators = (
        # Data flows from Message subject/body/html into the send call.
        # When Mail.send(msg) is called, taint from msg propagates.
        FlowPropagatorPattern(
            fqn="flask_mail.Mail.send",
            input_arg=0,
            output="receiver",
            description="Message taint propagates through send operation",
        ),
        FlowPropagatorPattern(
            fqn="flask_mail.Connection.send",
            input_arg=0,
            output="receiver",
            description="Message taint propagates through connection send",
        ),
    )

    # =================================================================
    # Taint sinks: email header injection
    # =================================================================

    sinks = (
        # If user input flows into Message.subject or recipients,
        # it could be an email header injection vector.
        # The Message constructor takes subject as arg 0.
        TaintSinkPattern(
            fqn="flask_mail.Message",
            arg=0,
            keyword="subject",
            sink_kind="EMAIL_HEADER_INJECTION",
            description=(
                "User input in email subject may allow header injection "
                "if newlines are not stripped"
            ),
        ),
        TaintSinkPattern(
            fqn="flask_mail.Message",
            arg=1,
            keyword="recipients",
            sink_kind="EMAIL_HEADER_INJECTION",
            when=~kwarg("recipients").is_literal_string(),
            description="User input in email recipients may enable relay abuse",
        ),
    )

    # =================================================================
    # Lifecycle registration
    # =================================================================

    lifecycle = (
        LifecycleRegistrationPattern(
            registration_fqn="flask_mail.Mail.init_app",
            hook_type=HookType.TEARDOWN,
            description="Registers Flask-Mail state with app extensions",
        ),
    )
