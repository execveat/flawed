"""django-allauth provider -- social auth, account management, and MFA.

Covers:
- Account decorators: ``@login_required``, ``@verified_email_required``
- Login/logout state writes: ``perform_login``, ``perform_logout``
- Social auth connection: ``SocialLogin.lookup``, ``SocialLogin.connect``
- Email notifications: ``DefaultAccountAdapter.send_mail``,
  ``DefaultAccountAdapter.send_confirmation_mail``
- MFA verification: ``TOTP.validate_code``, ``get_adapter().validate_totp``
- Signals: ``user_signed_up``, ``user_logged_in``, ``user_logged_out``,
  ``social_account_added``, ``social_account_updated``,
  ``email_confirmed``, ``email_confirmation_sent``

FQNs based on django-allauth 65.x public API.  allauth re-exports
decorators at ``allauth.account.decorators.*`` and utilities at
``allauth.account.utils.*``; both are declared where user code may
reference either path.
"""

from __future__ import annotations

from flawed._semantic.providers._base import (
    CheckKind,
    DispatchPattern,
    EffectCallPattern,
    FlowPropagatorPattern,
    HookType,
    LifecycleRegistrationPattern,
    Provider,
    ProviderMeta,
    SecurityCheckPattern,
)


class DjangoAllAuthProvider(Provider):
    meta = ProviderMeta(
        id="django-allauth",
        name="django-allauth",
        version="0.1.0",
        library="django-allauth",
        library_fqn="allauth",
    )

    # =================================================================
    # Security guard decorators
    # =================================================================

    checks = (
        # -- Account-level authentication guards ----------------------
        SecurityCheckPattern(
            fqn="allauth.account.decorators.login_required",
            kind=CheckKind.DECORATOR,
            category="AUTHENTICATION",
            description="Requires authenticated user (allauth-aware)",
        ),
        SecurityCheckPattern(
            fqn="allauth.account.decorators.verified_email_required",
            kind=CheckKind.DECORATOR,
            category="EMAIL_VERIFICATION",
            description="Requires authenticated user with verified email",
        ),
        # -- Reauthentication -----------------------------------------
        SecurityCheckPattern(
            fqn="allauth.account.decorators.reauthentication_required",
            kind=CheckKind.DECORATOR,
            category="REAUTHENTICATION",
            description="Requires user to re-authenticate before proceeding",
        ),
        # -- Password verification ------------------------------------
        SecurityCheckPattern(
            fqn="allauth.account.adapter.DefaultAccountAdapter.authenticate",
            kind=CheckKind.METHOD_CALL,
            category="AUTHENTICATION",
            description="Authenticates user with credentials via adapter",
        ),
        # -- MFA / TOTP verification ----------------------------------
        SecurityCheckPattern(
            fqn="allauth.mfa.totp.TOTP.validate_code",
            kind=CheckKind.METHOD_CALL,
            category="TWO_FACTOR_VERIFY",
            description="Validates a TOTP code for MFA",
        ),
        SecurityCheckPattern(
            fqn="allauth.mfa.totp.TOTP.activate",
            kind=CheckKind.METHOD_CALL,
            category="TWO_FACTOR_SETUP",
            description="Activates TOTP for user (enrolls 2FA)",
        ),
        SecurityCheckPattern(
            fqn="allauth.mfa.totp.TOTP.deactivate",
            kind=CheckKind.METHOD_CALL,
            category="TWO_FACTOR_SETUP",
            description="Deactivates TOTP for user (unenrolls 2FA)",
        ),
        SecurityCheckPattern(
            fqn="allauth.mfa.recovery_codes.RecoveryCodes.validate_code",
            kind=CheckKind.METHOD_CALL,
            category="TWO_FACTOR_VERIFY",
            description="Validates MFA recovery code",
        ),
        # -- Social token verification --------------------------------
        SecurityCheckPattern(
            fqn="allauth.socialaccount.providers.oauth2.views.OAuth2Adapter.complete_login",
            kind=CheckKind.METHOD_CALL,
            category="SOCIAL_AUTH",
            description="Completes OAuth2 social login (token exchange)",
        ),
        SecurityCheckPattern(
            fqn="allauth.socialaccount.helpers.complete_connect",
            kind=CheckKind.CALL,
            category="SOCIAL_AUTH",
            description="Completes social account connection",
        ),
    )

    # =================================================================
    # State-writing effects
    # =================================================================

    effects = (
        # -- Login/logout: session state mutations --------------------
        EffectCallPattern(
            fqn="allauth.account.utils.perform_login",
            category="STATE_WRITE",
            scope="SESSION",
            description="Logs user in via allauth -- writes auth state to session",
        ),
        EffectCallPattern(
            fqn="allauth.account.internal.flows.login.perform_login",
            category="STATE_WRITE",
            scope="SESSION",
            description="Logs user in via internal flow (allauth >=0.57)",
        ),
        EffectCallPattern(
            fqn="allauth.account.utils.perform_logout",
            category="STATE_WRITE",
            scope="SESSION",
            description="Logs user out -- clears session auth state",
        ),
        # -- Signup: creates user + writes session --------------------
        EffectCallPattern(
            fqn="allauth.account.utils.complete_signup",
            category="STATE_WRITE",
            scope="SESSION",
            description="Completes signup -- creates user and logs in",
        ),
        EffectCallPattern(
            fqn="allauth.account.utils.setup_user_email",
            category="DB_WRITE",
            description="Creates EmailAddress record for new user",
        ),
        # -- Social account connection --------------------------------
        EffectCallPattern(
            fqn="allauth.socialaccount.models.SocialLogin.connect",
            category="DB_WRITE",
            description="Links social account to user (creates SocialAccount row)",
        ),
        EffectCallPattern(
            fqn="allauth.socialaccount.models.SocialLogin.lookup",
            category="DB_READ",
            description="Looks up existing social account by UID",
        ),
        EffectCallPattern(
            fqn="allauth.socialaccount.models.SocialAccount.get_provider_account",
            category="DB_READ",
            description="Loads provider-specific account wrapper",
        ),
        # -- Email confirmation state ---------------------------------
        EffectCallPattern(
            fqn="allauth.account.models.EmailConfirmation.confirm",
            category="DB_WRITE",
            description="Marks email as verified (sets EmailAddress.verified=True)",
        ),
        EffectCallPattern(
            fqn="allauth.account.models.EmailConfirmation.send",
            category="NOTIFICATION",
            description="Sends email confirmation message",
        ),
        # -- Notifications: email sending via adapter -----------------
        EffectCallPattern(
            fqn="allauth.account.adapter.DefaultAccountAdapter.send_mail",
            category="NOTIFICATION",
            description="Sends templated email via allauth account adapter",
        ),
        EffectCallPattern(
            fqn="allauth.account.adapter.DefaultAccountAdapter.send_confirmation_mail",
            category="NOTIFICATION",
            description="Sends email confirmation link",
        ),
        # -- Password management --------------------------------------
        EffectCallPattern(
            fqn="allauth.account.internal.flows.password_change.change_password",
            category="DB_WRITE",
            description="Changes user password",
        ),
        EffectCallPattern(
            fqn="allauth.account.internal.flows.password_reset.reset_password",
            category="DB_WRITE",
            description="Resets user password from token",
        ),
        # -- MFA state ------------------------------------------------
        EffectCallPattern(
            fqn="allauth.mfa.totp.TOTP.instance",
            category="DB_READ",
            description="Loads TOTP authenticator for user",
        ),
        EffectCallPattern(
            fqn="allauth.mfa.recovery_codes.RecoveryCodes.generate",
            category="DB_WRITE",
            description="Generates new MFA recovery codes for user",
        ),
        # -- Social token storage -------------------------------------
        EffectCallPattern(
            fqn="allauth.socialaccount.models.SocialToken.save",
            category="DB_WRITE",
            description="Persists OAuth access/refresh token",
        ),
    )

    # =================================================================
    # Flow propagation
    # =================================================================

    propagators = (
        # Social login complete_login returns SocialLogin with user data
        FlowPropagatorPattern(
            fqn="allauth.socialaccount.providers.oauth2.views.OAuth2Adapter.complete_login",
            input_arg=0,
            output="return",
            description="OAuth2 token data flows to SocialLogin object",
        ),
        # SocialLogin.connect: social data flows to user record
        FlowPropagatorPattern(
            fqn="allauth.socialaccount.models.SocialLogin.connect",
            input_arg=0,
            output="receiver",
            description="Social account data flows to connected user",
        ),
    )

    # =================================================================
    # Lifecycle registration
    # =================================================================

    lifecycle = (
        # allauth middleware or INSTALLED_APPS registration installs
        # its own before_request equivalent for Django
        LifecycleRegistrationPattern(
            registration_fqn="allauth.account.middleware.AccountMiddleware",
            hook_type=HookType.BEFORE_HANDLER,
            description="allauth account middleware (login state, pending flows)",
        ),
    )

    # =================================================================
    # Dispatch patterns -- signals
    # =================================================================

    dispatches = (
        # Account signals
        DispatchPattern(
            source_fqn="allauth.account.signals.user_signed_up",
            target_method_names=("send",),
            dispatch_type="signal",
            description="Fired after a new user completes signup",
        ),
        DispatchPattern(
            source_fqn="allauth.account.signals.user_logged_in",
            target_method_names=("send",),
            dispatch_type="signal",
            description="Fired after successful login",
        ),
        DispatchPattern(
            source_fqn="allauth.account.signals.user_logged_out",
            target_method_names=("send",),
            dispatch_type="signal",
            description="Fired after logout",
        ),
        DispatchPattern(
            source_fqn="allauth.account.signals.email_confirmed",
            target_method_names=("send",),
            dispatch_type="signal",
            description="Fired after email address is confirmed",
        ),
        DispatchPattern(
            source_fqn="allauth.account.signals.email_confirmation_sent",
            target_method_names=("send",),
            dispatch_type="signal",
            description="Fired after confirmation email is sent",
        ),
        DispatchPattern(
            source_fqn="allauth.account.signals.password_changed",
            target_method_names=("send",),
            dispatch_type="signal",
            description="Fired after password is changed",
        ),
        DispatchPattern(
            source_fqn="allauth.account.signals.password_reset",
            target_method_names=("send",),
            dispatch_type="signal",
            description="Fired after password is reset via token",
        ),
        # Social account signals
        DispatchPattern(
            source_fqn="allauth.socialaccount.signals.social_account_added",
            target_method_names=("send",),
            dispatch_type="signal",
            description="Fired after social account is linked to user",
        ),
        DispatchPattern(
            source_fqn="allauth.socialaccount.signals.social_account_updated",
            target_method_names=("send",),
            dispatch_type="signal",
            description="Fired after social account data is refreshed",
        ),
        DispatchPattern(
            source_fqn="allauth.socialaccount.signals.social_account_removed",
            target_method_names=("send",),
            dispatch_type="signal",
            description="Fired after social account is unlinked from user",
        ),
        DispatchPattern(
            source_fqn="allauth.socialaccount.signals.pre_social_login",
            target_method_names=("send",),
            dispatch_type="signal",
            description="Fired before social login is processed",
        ),
    )
