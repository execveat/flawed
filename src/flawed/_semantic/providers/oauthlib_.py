"""oauthlib provider -- OAuth 2.0 core protocol library.

Covers the ``oauthlib.oauth2`` server-side endpoints and the
``RequestValidator`` subclass hooks that applications override.
oauthlib is framework-agnostic; integrations like Authlib and
Flask-OAuthlib build on top.
"""

from __future__ import annotations

from flawed._semantic.providers._base import (
    CheckKind,
    EffectCallPattern,
    FlowPropagatorPattern,
    Provider,
    ProviderMeta,
    SecurityCheckPattern,
)


class OAuthLibProvider(Provider):
    meta = ProviderMeta(
        id="oauthlib",
        name="OAuthLib",
        version="0.1.0",
        library="oauthlib",
        library_fqn="oauthlib",
    )

    # -- Security checks -------------------------------------------------

    checks = (
        # Token verification on resource endpoints
        SecurityCheckPattern(
            fqn="oauthlib.oauth2.rfc6749.endpoints.resource.ResourceEndpoint.verify_request",
            kind=CheckKind.METHOD_CALL,
            category="TOKEN_VERIFY",
            description="Verify bearer token on resource request",
        ),
        # RequestValidator hooks -- subclass overrides act as guards
        SecurityCheckPattern(
            fqn="oauthlib.oauth2.rfc6749.request_validator.RequestValidator.authenticate_client",
            kind=CheckKind.METHOD_CALL,
            category="AUTHENTICATION",
            description="Authenticate OAuth client credentials",
        ),
        SecurityCheckPattern(
            fqn="oauthlib.oauth2.rfc6749.request_validator.RequestValidator.authenticate_client_id",
            kind=CheckKind.METHOD_CALL,
            category="AUTHENTICATION",
            description="Authenticate client by client_id only (public clients)",
        ),
        SecurityCheckPattern(
            fqn="oauthlib.oauth2.rfc6749.request_validator.RequestValidator.validate_bearer_token",
            kind=CheckKind.METHOD_CALL,
            category="TOKEN_VERIFY",
            description="Validate bearer token and scopes",
        ),
        SecurityCheckPattern(
            fqn="oauthlib.oauth2.rfc6749.request_validator.RequestValidator.validate_client_id",
            kind=CheckKind.METHOD_CALL,
            category="AUTHORIZATION",
            description="Validate that client_id is a registered client",
        ),
        SecurityCheckPattern(
            fqn="oauthlib.oauth2.rfc6749.request_validator.RequestValidator.validate_code",
            kind=CheckKind.METHOD_CALL,
            category="TOKEN_VERIFY",
            description="Validate authorization code",
        ),
        SecurityCheckPattern(
            fqn="oauthlib.oauth2.rfc6749.request_validator.RequestValidator.validate_grant_type",
            kind=CheckKind.METHOD_CALL,
            category="AUTHORIZATION",
            description="Validate grant type is allowed for client",
        ),
        SecurityCheckPattern(
            fqn="oauthlib.oauth2.rfc6749.request_validator.RequestValidator.validate_redirect_uri",
            kind=CheckKind.METHOD_CALL,
            category="AUTHORIZATION",
            description="Validate redirect_uri against registered URIs",
        ),
        SecurityCheckPattern(
            fqn="oauthlib.oauth2.rfc6749.request_validator.RequestValidator.validate_refresh_token",
            kind=CheckKind.METHOD_CALL,
            category="TOKEN_VERIFY",
            description="Validate refresh token",
        ),
        SecurityCheckPattern(
            fqn="oauthlib.oauth2.rfc6749.request_validator.RequestValidator.validate_response_type",
            kind=CheckKind.METHOD_CALL,
            category="AUTHORIZATION",
            description="Validate response_type is allowed for client",
        ),
        SecurityCheckPattern(
            fqn="oauthlib.oauth2.rfc6749.request_validator.RequestValidator.validate_scopes",
            kind=CheckKind.METHOD_CALL,
            category="AUTHORIZATION",
            description="Validate requested scopes are allowed for client",
        ),
        SecurityCheckPattern(
            fqn="oauthlib.oauth2.rfc6749.request_validator.RequestValidator.validate_user",
            kind=CheckKind.METHOD_CALL,
            category="AUTHENTICATION",
            description="Validate resource owner credentials (password grant)",
        ),
        SecurityCheckPattern(
            fqn="oauthlib.oauth2.rfc6749.request_validator.RequestValidator.confirm_redirect_uri",
            kind=CheckKind.METHOD_CALL,
            category="AUTHORIZATION",
            description="Confirm redirect_uri matches the one used in authorization",
        ),
    )

    # -- Effects ---------------------------------------------------------

    effects = (
        # Authorization endpoint -- creates authorization response
        EffectCallPattern(
            fqn="oauthlib.oauth2.rfc6749.endpoints.authorization.AuthorizationEndpoint.create_authorization_response",
            category="RESPONSE_WRITE",
            description="Create OAuth authorization response (redirect with code/token)",
        ),
        # Token endpoint -- creates token response
        EffectCallPattern(
            fqn="oauthlib.oauth2.rfc6749.endpoints.token.TokenEndpoint.create_token_response",
            category="RESPONSE_WRITE",
            description="Create OAuth token response (access_token + optional refresh)",
        ),
        # Token revocation
        EffectCallPattern(
            fqn="oauthlib.oauth2.rfc6749.request_validator.RequestValidator.revoke_token",
            category="STATE_WRITE",
            scope="SERVER",
            description="Revoke an access or refresh token",
        ),
        # Token/code persistence
        EffectCallPattern(
            fqn="oauthlib.oauth2.rfc6749.request_validator.RequestValidator.save_authorization_code",
            category="STATE_WRITE",
            scope="SERVER",
            description="Persist authorization code for later exchange",
        ),
        EffectCallPattern(
            fqn="oauthlib.oauth2.rfc6749.request_validator.RequestValidator.save_token",
            category="STATE_WRITE",
            scope="SERVER",
            description="Persist issued access/refresh token",
        ),
        EffectCallPattern(
            fqn="oauthlib.oauth2.rfc6749.request_validator.RequestValidator.save_bearer_token",
            category="STATE_WRITE",
            scope="SERVER",
            description="Persist issued bearer token (legacy alias for save_token)",
        ),
        EffectCallPattern(
            fqn="oauthlib.oauth2.rfc6749.request_validator.RequestValidator.invalidate_authorization_code",
            category="STATE_WRITE",
            scope="SERVER",
            description="Invalidate authorization code after exchange",
        ),
    )

    # -- Flow propagation ------------------------------------------------

    propagators = (
        # verify_request returns (valid, request) -- taint on request
        FlowPropagatorPattern(
            fqn="oauthlib.oauth2.rfc6749.endpoints.resource.ResourceEndpoint.verify_request",
            input_arg=0,
            output="return",
            description="Request URI taint propagates to verified request object",
        ),
    )
