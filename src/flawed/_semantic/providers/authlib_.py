"""authlib provider -- OAuth/OIDC client and resource server.

Authlib provides both OAuth client (consuming external OAuth providers)
and OAuth server (protecting local resources) functionality.

Security-relevant patterns:

**Client side** (``authlib.integrations.flask_client``):

- ``OAuth.init_app()`` / ``OAuth.register()`` -- lifecycle + config
- ``FlaskOAuth2App.authorize_redirect()`` -- initiates OAuth flow (redirect)
- ``FlaskOAuth2App.authorize_access_token()`` -- exchanges code for token;
  the returned token/claims are an input source (attacker-controlled
  if the OAuth provider is compromised or misconfigured).

**Server side** (``authlib.integrations.flask_oauth2``):

- ``ResourceProtector.acquire_token()`` -- security check (verifies
  bearer token on incoming requests)
- ``AuthorizationServer.create_token_response()`` -- token issuance

**JOSE** (``authlib.jose``):

- ``JsonWebToken.encode()`` / ``.decode()`` -- JWT operations
"""

from __future__ import annotations

from flawed._semantic.providers._base import (
    CheckKind,
    ClaimContainerPattern,
    EffectCallPattern,
    FlowPropagatorPattern,
    HookType,
    LifecycleRegistrationPattern,
    Provider,
    ProviderMeta,
    SecurityCheckPattern,
)


class AuthlibProvider(Provider):
    meta = ProviderMeta(
        id="authlib",
        name="Authlib",
        version="0.1.0",
        library="Authlib",
        library_fqn="authlib",
    )

    # =================================================================
    # Lifecycle: OAuth client initialization
    # =================================================================

    lifecycle = (
        LifecycleRegistrationPattern(
            registration_fqn="authlib.integrations.flask_client.OAuth.init_app",
            hook_type=HookType.BEFORE_HANDLER,
            description="Initialize OAuth client integration with Flask app",
        ),
    )

    # =================================================================
    # Inputs: the token-exchange result is an OAuth/OIDC claims container
    # =================================================================

    inputs = (
        # ``token = authorize_access_token()`` / ``parse_id_token()`` returns a
        # userinfo/claims container; keyed reads on it (and on values navigated
        # out of it, e.g. ``token["userinfo"].get("email")``) are provider
        # claims.  Matched by bare method name because the OAuth client object is
        # obtained from ``oauth.register(...)``, whose return type the index
        # cannot resolve — the FQN/receiver-type path would miss the call.
        ClaimContainerPattern(
            fqn=(
                "authlib.integrations.flask_client.apps.FlaskOAuth2App.authorize_access_token",
                "authlib.integrations.flask_client.apps.FlaskOAuth1App.authorize_access_token",
                "authlib.integrations.flask_client.apps.FlaskOAuth2App.parse_id_token",
            ),
            names=("authorize_access_token", "parse_id_token"),
            description="OAuth/OIDC token-exchange result is a userinfo/claims container",
        ),
    )

    # =================================================================
    # Effects: OAuth configuration and token operations
    # =================================================================

    effects = (
        # OAuth provider registration modifies server-wide config
        EffectCallPattern(
            fqn="authlib.integrations.flask_client.OAuth.register",
            category="CONFIG_WRITE",
            scope="SERVER",
            description="Register an OAuth provider (client_id, client_secret, URLs)",
        ),
        # authorize_redirect sends the user to the OAuth provider.  The OAuth
        # client is obtained from a registry attribute (``oauth.<provider>``) or
        # an ``oauth.register(...)`` result, whose type the index cannot
        # resolve, so this is *also* matched by the federation-specific bare
        # method name (mirroring the ClaimContainerPattern above).  OAuth1 and
        # OAuth2 share one descriptor so a single call yields one effect, not two.
        EffectCallPattern(
            fqn=(
                "authlib.integrations.flask_client.apps.FlaskOAuth2App.authorize_redirect",
                "authlib.integrations.flask_client.apps.FlaskOAuth1App.authorize_redirect",
            ),
            # Configured-target: the redirect (and any OIDC discovery/metadata
            # fetch it triggers) goes to the *registered* IdP, never a
            # caller-supplied URL -- a real outbound for timeout/coverage rules
            # but not an SSRF sink.
            category="OUTBOUND_REQUEST_CONFIGURED",
            names=("authorize_redirect",),
            description="Redirect user to OAuth provider for authorization",
        ),
        # authorize_access_token exchanges auth code for token (outbound HTTP);
        # same registry-attribute receiver problem -> bare-name matched.
        EffectCallPattern(
            fqn=(
                "authlib.integrations.flask_client.apps.FlaskOAuth2App.authorize_access_token",
                "authlib.integrations.flask_client.apps.FlaskOAuth1App.authorize_access_token",
            ),
            # Configured-target: the token exchange is an HTTP call to the
            # *registered* IdP token endpoint, not a caller-supplied URL.  Marking
            # it configured-target stops taint-to-sink (SSRF) rules from pairing
            # the OAuth token/claim this very call returns with the call itself
            # (FLAW-276) while keeping it visible to outbound timeout/coverage rules.
            category="OUTBOUND_REQUEST_CONFIGURED",
            names=("authorize_access_token",),
            description="Exchange authorization code for access token (HTTP to provider)",
        ),
        # Token creation on server side
        EffectCallPattern(
            fqn="authlib.integrations.flask_oauth2.authorization_server.AuthorizationServer.create_token_response",
            category="STATE_WRITE",
            scope="SESSION",
            description="Issue OAuth access/refresh token to client",
        ),
        # JWT encode (token creation)
        EffectCallPattern(
            fqn="authlib.jose.rfc7519.jwt.JsonWebToken.encode",
            category="STATE_WRITE",
            scope="SESSION",
            description="Create signed JWT",
        ),
    )

    # =================================================================
    # Security checks: token verification
    # =================================================================

    checks = (
        # Resource protector verifies bearer token on each request
        SecurityCheckPattern(
            fqn="authlib.integrations.flask_oauth2.resource_protector.ResourceProtector.acquire_token",
            kind=CheckKind.METHOD_CALL,
            category="TOKEN_VERIFY",
            description="Verify bearer token and load token object",
        ),
        # JWT decode verifies signature
        SecurityCheckPattern(
            fqn="authlib.jose.rfc7519.jwt.JsonWebToken.decode",
            kind=CheckKind.CALL,
            category="TOKEN_VERIFY",
            description="Verify JWT signature and decode claims",
        ),
        # AuthorizationServer.validate_authorization_request
        SecurityCheckPattern(
            fqn="authlib.integrations.flask_oauth2.authorization_server.AuthorizationServer.validate_authorization_request",
            kind=CheckKind.METHOD_CALL,
            category="AUTHORIZATION",
            description="Validate OAuth authorization request parameters",
        ),
    )

    # =================================================================
    # Flow propagation
    # =================================================================

    propagators = (
        # Token claims flow from authorize_access_token to returned dict.
        # The OAuth client is typically obtained from ``oauth.register(...)``
        # (``oauth.<provider>.authorize_access_token()``), a registry attribute
        # whose return type the index cannot resolve, so FQN/receiver-type paths
        # miss the call; ``names`` closes that token-flow false negative.  The
        # method name is federation-specific enough that a bare-name match is
        # sound (mirrors the ClaimContainerPattern names= escape hatch).
        FlowPropagatorPattern(
            fqn="authlib.integrations.flask_client.apps.FlaskOAuth2App.authorize_access_token",
            names=("authorize_access_token",),
            input_arg=0,
            output="return",
            description="OAuth token/claims flow from provider response to return value",
        ),
        # JWT decode: token → claims
        FlowPropagatorPattern(
            fqn="authlib.jose.rfc7519.jwt.JsonWebToken.decode",
            input_arg=0,
            output="return",
            description="JWT claims flow from encoded token to decoded payload",
        ),
        # JWT encode: payload → token
        FlowPropagatorPattern(
            fqn="authlib.jose.rfc7519.jwt.JsonWebToken.encode",
            input_arg=1,
            output="return",
            description="Payload data flows into encoded JWT string",
        ),
    )
