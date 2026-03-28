"""Provider base class and declarative DSL for semantic layer providers.

A **provider** supplies framework/library-specific knowledge to the
Semantic Layer.  Providers are mostly declarative -- class-level
attributes describe patterns; the Semantic Layer engine matches them
against Layer 1 facts.

Providers have three levels of expressiveness, from simplest to most
powerful:

1. **Declarative data** -- class attributes holding frozen descriptor
   tuples.  Covers ~80% of real-world patterns (FQN matches, simple
   attribute access).

2. **Predicate descriptors** -- declarative data augmented with a
   ``when=`` guard that receives a lightweight match context.  Covers
   conditional patterns like ``session.execute(Insert(...))`` vs
   ``session.execute(Select(...))``.

3. **Custom extraction methods** -- override ``extract_*`` hooks that
   receive the full ``CodeIndex`` and return domain objects directly.
   Covers complex structural patterns like class-based view dispatch
   correlation or router-group URL-prefix chaining.

The three levels are additive: a provider can mix all three in the
same class.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import ClassVar

# =====================================================================
# Provider metadata
# =====================================================================


@dataclass(frozen=True)
class ProviderMeta:
    """Metadata identifying a provider.

    Attributes:
        id: Short stable identifier (e.g. ``"flask"``, ``"flask-login"``).
            Used in config files to enable/disable/configure.
        name: Human-readable display name.
        version: Semver string for the provider itself (not the target library).
        library: The PyPI package name this provider targets (e.g. ``"Flask"``).
        library_fqn: Root import FQN used to auto-detect applicability
            (e.g. ``"flask"``).  When this FQN appears in a repo's imports,
            the provider is auto-activated (unless manually disabled).
            ``"builtins"`` is treated as always available because built-in
            functions have call FQNs but no corresponding import facts.
        activation_imports: Additional root import FQNs that also auto-activate
            this provider, for libraries that wrap or re-export the target
            library. A flask-sqlalchemy app, for example, imports only
            ``flask_sqlalchemy`` yet exercises the SQLAlchemy ORM (its
            ``Model.query`` chains canonicalize to ``sqlalchemy.orm`` FQNs), so
            the SQLAlchemy provider declares ``activation_imports=
            ("flask_sqlalchemy",)`` to fire even when ``sqlalchemy`` is never
            imported directly.
    """

    id: str
    name: str
    version: str = "0.1.0"
    library: str = ""
    library_fqn: str = ""
    activation_imports: tuple[str, ...] = ()


# =====================================================================
# Match context -- passed to ``when=`` predicates
# =====================================================================


class ArgRef:
    """Lightweight reference to a call-site argument for predicate building.

    Used in ``when=`` guards::

        when = arg(0).type_is("sqlalchemy.sql.dml.Insert")
    """

    def __init__(self, position: int | None = None, keyword: str | None = None) -> None:
        self.position = position
        self.keyword = keyword

    def type_is(self, fqn: str) -> WhenPredicate:
        """True when the argument's inferred type matches *fqn*."""
        return TypeCheckPredicate(arg_pos=self.position, arg_kw=self.keyword, type_fqn=fqn)

    def type_in(self, *fqns: str) -> WhenPredicate:
        """True when the argument's inferred type matches any of *fqns*."""
        return TypeCheckPredicate(
            arg_pos=self.position, arg_kw=self.keyword, type_fqn=fqns[0], alt_fqns=fqns[1:]
        )

    def is_literal_string(self) -> WhenPredicate:
        """True when the argument is a compile-time string literal."""
        return LiteralStringPredicate(arg_pos=self.position, arg_kw=self.keyword)


def arg(position: int) -> ArgRef:
    """Create an argument reference by position for ``when=`` predicates."""
    return ArgRef(position=position)


def kwarg(name: str) -> ArgRef:
    """Create an argument reference by keyword for ``when=`` predicates."""
    return ArgRef(keyword=name)


# =====================================================================
# When-predicates  (frozen, composable)
# =====================================================================


@dataclass(frozen=True)
class WhenPredicate:
    """Base for predicate descriptors used in ``when=`` guards."""

    def __and__(self, other: WhenPredicate) -> WhenPredicate:
        return AndPredicate(left=self, right=other)

    def __or__(self, other: WhenPredicate) -> WhenPredicate:
        return OrPredicate(left=self, right=other)

    def __invert__(self) -> WhenPredicate:
        return NotPredicate(inner=self)


@dataclass(frozen=True)
class TypeCheckPredicate(WhenPredicate):
    arg_pos: int | None = None
    arg_kw: str | None = None
    type_fqn: str = ""
    alt_fqns: tuple[str, ...] = ()


@dataclass(frozen=True)
class LiteralStringPredicate(WhenPredicate):
    arg_pos: int | None = None
    arg_kw: str | None = None


@dataclass(frozen=True)
class AndPredicate(WhenPredicate):
    left: WhenPredicate = field(default_factory=WhenPredicate)
    right: WhenPredicate = field(default_factory=WhenPredicate)


@dataclass(frozen=True)
class OrPredicate(WhenPredicate):
    left: WhenPredicate = field(default_factory=WhenPredicate)
    right: WhenPredicate = field(default_factory=WhenPredicate)


@dataclass(frozen=True)
class NotPredicate(WhenPredicate):
    inner: WhenPredicate = field(default_factory=WhenPredicate)


# =====================================================================
# Descriptor types -- one per extension-point category
# =====================================================================


# --- EP-1: Routes ---


@dataclass(frozen=True)
class RouteDecorator:
    """Declares that a decorator FQN registers an HTTP route.

    Attributes:
        fqn: FQN of the decorator, or tuple of FQN aliases that all
            refer to the same API (e.g. Flask.route and Blueprint.route).
        rule_arg: Positional index of the URL rule argument.
        methods_kwarg: Keyword name of the methods argument.
        default_methods: Methods assumed when ``methods`` is not given.
        implied_method: If set, this decorator implies a single HTTP
            method (e.g. ``@app.get`` implies GET).
    """

    fqn: str | tuple[str, ...]
    rule_arg: int = 0
    methods_kwarg: str = "methods"
    default_methods: tuple[str, ...] = ("GET",)
    implied_method: str | None = None


@dataclass(frozen=True)
class RouteCallPattern:
    """Declares that a function call registers a route imperatively.

    Matches ``app.add_url_rule("/path", view_func=fn)`` patterns.
    """

    fqn: str | tuple[str, ...]
    rule_arg: int = 0
    view_func_kwarg: str = "view_func"
    methods_kwarg: str = "methods"


@dataclass(frozen=True)
class ClassViewPattern:
    """Declares a class-based view that dispatches by HTTP method.

    The provider gives the base class FQN; the engine finds subclasses
    and maps method names (get, post, etc.) to HTTP verbs.
    """

    base_class_fqn: str | tuple[str, ...]
    method_map: dict[str, str] = field(
        default_factory=lambda: {
            "get": "GET",
            "post": "POST",
            "put": "PUT",
            "delete": "DELETE",
            "patch": "PATCH",
        }
    )
    as_view_method: str = "as_view"


@dataclass(frozen=True)
class ImperativeRoutePattern:
    """Declares that routes are defined by items in a module-level list.

    Covers Django ``urlpatterns``, Tornado ``Application`` handlers,
    Starlette ``Route(...)`` objects, and similar patterns where routes
    are assembled as data structures rather than applied as decorators.

    The engine scans for assignments to ``list_variable`` and extracts
    route entries from the constructor calls matching ``entry_fqn``.

    Attributes:
        entry_fqn: FQN of the constructor that creates a route entry
            (e.g. ``"django.urls.path"``, ``"starlette.routing.Route"``).
        rule_arg: Positional index of the URL pattern argument.
        view_arg: Positional index of the view/handler argument.
        view_kwarg: Keyword name of the view/handler argument.
        methods_arg: Positional index of the methods argument (if any).
        methods_kwarg: Keyword name of the methods argument (if any).
        list_variable: Expected name of the module-level variable
            holding the route list (e.g. ``"urlpatterns"``).  ``None``
            means the engine scans for any list containing ``entry_fqn``
            constructor calls.
        nested_fqn: FQN for nested route groups (e.g. ``"django.urls.include"``).
            ``None`` if the framework has no nesting mechanism.
    """

    entry_fqn: str | tuple[str, ...]
    rule_arg: int = 0
    view_arg: int = 1
    view_kwarg: str = "view"
    methods_arg: int | None = None
    methods_kwarg: str | None = "methods"
    list_variable: str | None = None
    nested_fqn: str | tuple[str, ...] | None = None


# --- EP-1b: Router group namespacing ---


@dataclass(frozen=True)
class RouterGroupPattern:
    """Declares a constructor that creates a named route-group namespace.

    Covers patterns such as Flask ``Blueprint``, FastAPI ``APIRouter``,
    Starlette ``Mount``, Django ``include()``, Sanic ``Blueprint``,
    Litestar ``Router``, and similar constructs where a subset of routes
    is grouped under a shared name and optional URL prefix.

    The engine scans module-level assignments for constructors matching
    ``constructor_fqn``, extracts the group name from the positional
    argument at ``name_arg``, and the URL prefix from ``prefix_kwarg``.

    Attributes:
        constructor_fqn: FQN of the constructor class, or tuple of
            FQN aliases.
        name_arg: Positional index of the group name argument.
        prefix_kwarg: Keyword argument name for the URL prefix.
        description: Human-readable description.
    """

    constructor_fqn: str | tuple[str, ...]
    name_arg: int = 0
    prefix_kwarg: str = "url_prefix"
    description: str = ""


@dataclass(frozen=True)
class RouterGroupMountPattern:
    """Declares a method call that mounts a route group into a parent.

    Covers patterns such as Flask ``app.register_blueprint()``, FastAPI
    ``app.include_router()``, Sanic ``app.blueprint()``, Litestar
    ``app.register()``, and similar mounts where a route group is
    attached to an application or parent group with an optional URL
    prefix override.

    The engine scans call edges for method calls matching
    ``mount_method`` on instances of ``app_fqn``, and extracts the URL
    prefix override from ``prefix_kwarg``.

    Attributes:
        app_fqn: FQN of the parent class (app or parent group), or
            tuple of FQN aliases.
        mount_method: Name of the mount method.
        group_arg: Positional index of the group argument.
        prefix_kwarg: Keyword argument name for URL prefix override.
        description: Human-readable description.
    """

    app_fqn: str | tuple[str, ...]
    mount_method: str
    group_arg: int = 0
    prefix_kwarg: str = "url_prefix"
    description: str = ""


# --- EP-2: Input sources ---


@dataclass(frozen=True)
class InputAttributePattern:
    """Declares that accessing an attribute on a type yields user input.

    Matches ``request.args``, ``request.form``, etc.
    """

    receiver_fqn: str | tuple[str, ...]
    attribute: str
    source_type: str  # InputSource subclass name: "Query", "Form", etc.
    cardinality: str = "SINGLE"  # "SINGLE" | "MULTI"
    description: str = ""


@dataclass(frozen=True)
class InputMethodPattern:
    """Declares that calling a method yields user input.

    Matches ``request.get_json()``, ``form.validate()``, etc.
    """

    fqn: str | tuple[str, ...]
    source_type: str
    key_arg: int | None = None  # positional arg that names the key
    key_kwarg: str | None = None  # keyword arg that names the key
    cardinality: str = "SINGLE"
    description: str = ""


@dataclass(frozen=True)
class InputFieldAccessPattern:
    """Declares that accessing a field attribute on a subclass yields input.

    Matches ``form.<field_name>.data`` where form is a FlaskForm subclass.
    """

    base_class_fqn: str | tuple[str, ...]
    field_attribute: str  # e.g. "data"
    source_type: str = "Form"
    cardinality: str = "SINGLE"
    description: str = ""


@dataclass(frozen=True)
class InputParameterPattern:
    """Declares that a function parameter's default value type determines
    its input source.

    Covers FastAPI, Litestar, and BlackSheep patterns where the input
    source is inferred from the type of the parameter default::

        @app.get("/items")
        async def read_items(
            q: str = Query(None),  # default type -> Query input
            limit: int = 10,  # plain default -> Query input
            item: Item = Body(...),  # default type -> Json input
        ): ...

    The engine inspects each parameter of matched handler functions
    and checks whether the default value is an instance of one of the
    registered ``default_type_fqn`` constructors.

    Attributes:
        default_type_fqn: FQN of the default-value constructor that
            signals this input source (e.g. ``"fastapi.Query"``).
        source_type: InputSource subclass name (``"Query"``, ``"Json"``,
            ``"Header"``, ``"Cookie"``, ``"PathParam"``, ``"Form"``,
            ``"FileUpload"``).
        key_from: How to determine the key name.  ``"param_name"``
            uses the parameter name; ``"alias"`` checks the ``alias``
            kwarg of the default constructor; ``"first_arg"`` uses
            the first positional arg.
        cardinality: ``"SINGLE"`` or ``"MULTI"``.
        description: Human-readable description.
    """

    default_type_fqn: str | tuple[str, ...]
    source_type: str
    key_from: str = "param_name"  # "param_name" | "alias" | "first_arg"
    cardinality: str = "SINGLE"
    description: str = ""


@dataclass(frozen=True)
class ClaimContainerPattern:
    """Declares that a call returns an OAuth/OIDC claims container.

    The return value of a federated-identity token exchange -- e.g.
    ``authorize_access_token()`` / ``parse_id_token()`` -- is a claims/userinfo
    container.  Keyed accesses on that value, **and on values navigated from it**
    (``token["userinfo"]`` then ``userinfo.get("email")``), are claim
    :class:`~flawed.inputs.InputRead` observations whose source is a
    :class:`~flawed.inputs.ProviderClaim` keyed by the access key.

    Matched by ``fqn`` **and/or** bare method ``names``.  Name matching is
    offered because the OAuth client object is typically obtained from a
    registry call (``oauth.register(...)``) whose return type the index cannot
    resolve, so the concrete-FQN / receiver-type path misses the producing call;
    the producing method names (``authorize_access_token`` / ``parse_id_token``)
    are federation-specific enough that bare-name matching is sound.  This
    mirrors :class:`ValidatedValueGuardPattern`'s ``names=`` escape hatch for
    project-local validators the type layer cannot reach.

    Attributes:
        fqn: Canonical FQN(s) of the claims-producing call, or ``None``.
        names: Bare method names to match receiver-type-independently.
        source_type: InputSource subclass name (default ``"ProviderClaim"``).
        description: Human-readable description.
    """

    fqn: str | tuple[str, ...] | None = None
    names: tuple[str, ...] = ()
    source_type: str = "ProviderClaim"
    description: str = ""


@dataclass(frozen=True)
class InputContainerPattern:
    """Declares that keyed access on a *module-global* container yields input.

    Unlike :class:`InputAttributePattern` (which anchors on a container
    *attribute* like ``request.args`` and then keys into it), this anchors
    directly on a global receiver -- Flask ``session`` / ``g`` -- where the
    keyed access **is** the read:

    - subscript ``session["cart_id"]`` -> ``source_type`` keyed by the subscript
    - method ``session.get("token")`` / ``.pop("token")`` -> keyed by ``arg0``
    - attribute ``g.cart_id`` -> keyed by the attribute name

    The container's keys are arbitrary per-app, so the access shape -- not a
    fixed attribute name -- is what's declared. The produced reads are typically
    *identity* sources (``SessionValue`` / ``FrameworkGlobal``); FP-containment
    (keeping them out of the wildcard ``reads()`` stream) is handled downstream
    by :attr:`~flawed.inputs.InputSource.is_identity_source`, not here.

    Attributes:
        receiver_fqn: Canonical FQN(s) of the global container.
        source_type: InputSource subclass name (``"SessionValue"``,
            ``"FrameworkGlobal"``).
        access: Which access shapes to match -- any of ``"subscript"``,
            ``"method"``, ``"attribute"``.
        key_methods: Method names whose first positional arg names the key
            (used only when ``"method"`` is in ``access``).
        cardinality: ``"SINGLE"`` or ``"MULTI"``.
        description: Human-readable description.
    """

    receiver_fqn: str | tuple[str, ...]
    source_type: str
    access: tuple[str, ...] = ("subscript", "method", "attribute")
    key_methods: tuple[str, ...] = ("get", "pop")
    cardinality: str = "SINGLE"
    description: str = ""


# --- EP-3 / EP-5: Effects (including state access) ---


@dataclass(frozen=True)
class EffectCallPattern:
    """Declares that calling a function produces a security-relevant effect.

    The simplest and most common descriptor.  Matches any call to
    the given FQN and labels it with a category.

    ``names`` is the receiver-type-independent escape hatch (mirroring
    :class:`ClaimContainerPattern` / :class:`ValidatedValueGuardPattern`): a
    call whose bare method name matches is labelled even when its receiver type
    cannot be resolved.  Use it only for federation-/library-specific method
    names distinctive enough that a bare-name match is sound — e.g. an OAuth
    client obtained via ``oauth.register(...)`` / ``oauth.<provider>`` (a
    registry attribute) whose type the index cannot resolve, so the concrete-FQN
    and receiver-type paths both miss the call.  Do NOT use it for generic names
    (``get``, ``add``) where bare-name matching would over-fire.

    Attributes:
        fqn: Fully qualified name of the function/method, or tuple
            of FQN aliases that all refer to the same API.
        category: The EffectCategory value name (e.g. ``"DB_WRITE"``).
        scope: Optional StateScope value name for state effects.
        keys: Optional state key names affected.
        when: Optional predicate for conditional matching.
        names: Bare method names to match receiver-type-independently.
        description: Human-readable description.
    """

    fqn: str | tuple[str, ...]
    category: str
    scope: str | None = None  # "REQUEST" | "SESSION" | "SERVER" | None
    keys: tuple[str, ...] = ()
    when: WhenPredicate | None = None
    names: tuple[str, ...] = ()
    description: str = ""


@dataclass(frozen=True)
class EffectAttributePattern:
    """Declares that writing to an attribute produces an effect.

    Matches ``g.user = value``, ``session["key"] = value``, etc.
    """

    receiver_fqn: str | tuple[str, ...]
    category: str
    scope: str | None = None
    description: str = ""


@dataclass(frozen=True)
class EffectSubscriptPattern:
    """Declares that subscript write on a type produces an effect.

    Matches ``session["key"] = value``.
    """

    receiver_fqn: str | tuple[str, ...]
    category: str
    scope: str | None = None
    description: str = ""


# --- EP-4 / EP-9: Security checks ---


class CheckKind(Enum):
    """How the security check manifests in code."""

    DECORATOR = "decorator"
    CALL = "call"
    METHOD_CALL = "method_call"


@dataclass(frozen=True)
class SecurityCheckPattern:
    """Declares that a function/decorator acts as a security guard.

    Attributes:
        fqn: FQN of the decorator or callable, or tuple of FQN
            aliases that all refer to the same API.
        kind: How it's used (decorator, call, method_call).
        category: Free-form category string (e.g. "AUTHENTICATION",
            "CSRF", "FORM_VALIDATION").  Extensible by providers.
        description: Human-readable description.
    """

    fqn: str | tuple[str, ...]
    kind: CheckKind
    category: str
    description: str = ""


@dataclass(frozen=True)
class ClassAttributeGuardPattern:
    """Declares that a class attribute on a view class acts as a guard.

    Covers Django REST Framework's ``permission_classes``,
    ``authentication_classes``, ``throttle_classes``; Falcon's
    ``auth_backend``; Litestar's ``guards`` attribute; and similar
    patterns where security policy is declared as a class attribute
    containing a list of guard classes.

    The engine scans classes that inherit from ``view_base_fqn`` and
    checks for the specified attribute.  Each class in the list is
    resolved and treated as a security guard of the given category.

    Attributes:
        view_base_fqn: FQN of the view base class (e.g.
            ``"rest_framework.views.APIView"``).
        attribute_name: Name of the class attribute (e.g.
            ``"permission_classes"``).
        guard_base_fqn: FQN of the base class for guard items
            (e.g. ``"rest_framework.permissions.BasePermission"``).
        category: Security check category (e.g. ``"AUTHORIZATION"``).
        empty_means_unprotected: When ``True``, an empty list means
            no guard is applied (fail-open).  Default ``False``.
        description: Human-readable description.
    """

    view_base_fqn: str | tuple[str, ...]
    attribute_name: str
    guard_base_fqn: str | tuple[str, ...]
    category: str
    empty_means_unprotected: bool = False
    description: str = ""


# --- EP-6: Lifecycle hooks ---


class HookType(Enum):
    """Framework-neutral lifecycle hook phases.

    Seven phases covering the full request lifecycle across all web
    frameworks.  Rule authors use these without knowing which framework
    the target application uses.

    =================  ============================================
    HookType           Framework equivalents
    =================  ============================================
    ``STARTUP``        FastAPI on_startup, Sanic before_server_start
    ``SHUTDOWN``       FastAPI on_shutdown, Sanic before_server_stop
    ``BEFORE_HANDLER`` Flask before_request, Django process_request /
                       process_view, Starlette middleware dispatch,
                       Falcon process_request, Tornado prepare
    ``AFTER_HANDLER``  Flask after_request, Django process_response,
                       Falcon process_response, Tornado on_finish
    ``ON_ERROR``       Flask errorhandler, Django process_exception
    ``TEARDOWN``       Flask teardown_request / teardown_appcontext
    ``SIGNAL``         Django signals, Flask blinker, SA events
    =================  ============================================
    """

    STARTUP = "startup"
    """Application startup -- runs once at boot."""

    SHUTDOWN = "shutdown"
    """Application shutdown -- runs once at stop."""

    BEFORE_HANDLER = "before_handler"
    """Runs before the route handler executes."""

    AFTER_HANDLER = "after_handler"
    """Runs after the route handler returns."""

    ON_ERROR = "on_error"
    """Runs when an exception occurs during request handling."""

    TEARDOWN = "teardown"
    """Cleanup after response is sent -- guaranteed to run."""

    SIGNAL = "signal"
    """Event/signal dispatch -- decoupled observer pattern."""


@dataclass(frozen=True)
class LifecycleDecoratorPattern:
    """Declares that a decorator registers a lifecycle hook."""

    fqn: str | tuple[str, ...]
    hook_type: HookType
    scope: str = "global"  # "global" | "group"
    description: str = ""


@dataclass(frozen=True)
class LifecycleRegistrationPattern:
    """Declares that init_app/setup registers a lifecycle hook implicitly.

    When ``check_category`` is set, the registration also installs a
    provider-owned security check of that category on every applicable
    route (e.g. ``CSRFProtect.init_app`` installs a ``"CSRF"`` check).

    ``when`` is an optional predicate (same vocabulary as ``EffectCallPattern``)
    that conditions the match on the call's arguments.  It is essential for
    extension *constructors* that only register when an app is passed: flask-wtf
    ``CSRFProtect(app)`` registers global CSRF, but the deferred ``CSRFProtect()``
    (bound later via ``init_app``) does not -- gating on ``arg(0)`` distinguishes
    the two so the bare constructor does not falsely mark routes as covered.
    """

    registration_fqn: str | tuple[str, ...]
    hook_type: HookType
    check_category: str | None = None
    when: WhenPredicate | None = None
    description: str = ""


@dataclass(frozen=True)
class CheckRegistrationPattern:
    """Declares that a call registers a provider-owned route check.

    This covers framework APIs where a security guard is attached to a
    routing container rather than directly to a handler function, such as a
    rate-limit decorator applied to a router group. The provider declares
    which call FQN performs the registration and which argument identifies the
    affected target; L2 conversion resolves that target generically.

    Attributes:
        registration_fqn: FQN of the registration call or tuple of aliases.
        hook_type: Request lifecycle phase where the provider-owned check runs.
        check_category: Security check category exposed via ``CodeScope.checks``.
        target_arg: Positional argument that names the affected target.
        target_kwarg: Keyword argument that names the affected target.
        target_kind: Target domain. Supported values are ``"router_group"``
            and ``"application"``.
        require_call_result_invocation: Only match calls that invoke the
            result of another call, e.g. ``factory(...)(target)``. Use this
            for decorator factories whose one-stage call form also appears in
            normal ``@decorator_factory(...)`` syntax.
        description: Human-readable description.
    """

    registration_fqn: str | tuple[str, ...]
    hook_type: HookType
    check_category: str
    target_arg: int | None = 0
    target_kwarg: str | None = None
    target_kind: str = "router_group"
    require_call_result_invocation: bool = False
    description: str = ""


@dataclass(frozen=True)
class ControlPlaneExemptionPattern:
    """Declares that a CALL exempts its named target from a control-plane guard.

    Covers framework APIs that disable a request-lifecycle guard for a specific
    target by naming it as an argument, typically at *module scope* with no
    enclosing route -- e.g. flask-wtf ``csrf.exempt(view)`` /
    ``csrf.exempt(blueprint)``.

    The decorator form (``@csrf.exempt``) is captured on the view function and
    surfaces via ``route.body.decorators()``.  The CALL form is a bare module
    statement whose effect has no enclosing function, so the ordinary
    :class:`EffectCallPattern` conversion drops it (``functions_by_fqn`` has no
    entry for the module -- ``_effect_conversion._convert_call_match``).  This
    pattern instead resolves the *argument* to its target view (single route)
    or blueprint (all routes under it) and attributes a control-plane-write
    exemption effect onto those route(s)' ``full_stack``, so effect-based
    consumers (e.g. ``is_csrf_exemption`` over ``Config.write()`` effects)
    recognise the exemption generically without a per-rule change.

    Attributes:
        registration_fqn: FQN of the exempting call, or a tuple of aliases.
        category: Effect category attributed to the target route(s).
        scope: Persistence scope for the attributed effect.
        target_arg: Positional argument that names the exempted target.
        target_kwarg: Keyword argument that names the exempted target.
        description: Human-readable description.
    """

    registration_fqn: str | tuple[str, ...]
    category: str = "CONFIG_WRITE"
    scope: str = "SERVER"
    target_arg: int | None = 0
    target_kwarg: str | None = None
    description: str = ""


@dataclass(frozen=True)
class MiddlewareClassPattern:
    """Declares that a class acts as middleware with hook methods.

    Covers Django's ``MiddlewareMixin`` (``process_request``,
    ``process_response``), Starlette's ``BaseHTTPMiddleware``
    (``dispatch``), Falcon's middleware (``process_request``,
    ``process_response``), and similar class-based middleware patterns.

    The engine finds subclasses of ``base_class_fqn`` and maps the
    listed method names to lifecycle hook types.

    Attributes:
        base_class_fqn: FQN of the middleware base class or mixin.
        method_hooks: Mapping of method name to ``HookType``.
            Example: ``{"process_request": HookType.BEFORE_HANDLER}``.
        description: Human-readable description.
    """

    base_class_fqn: str | tuple[str, ...]
    method_hooks: dict[str, HookType]
    description: str = ""


@dataclass(frozen=True)
class DependencyPattern:
    """Declares a dependency-injection parameter that serves a compound
    security role.

    Covers FastAPI's ``Depends()``, Litestar's ``Provide()``, and
    similar DI patterns where a single parameter default simultaneously:

    - Runs a callable before the handler (lifecycle hook)
    - Injects the callable's return value into the handler (input)
    - Can raise exceptions to deny access (security guard)

    The engine inspects handler parameters for defaults matching
    ``inject_fqn`` and resolves the dependency callable.

    Attributes:
        inject_fqn: FQN of the injection marker (e.g. ``"fastapi.Depends"``).
        callable_arg: Positional index of the dependency callable
            argument within the injection marker constructor.
        scope: How the engine treats the dependency callable:
            ``"lifecycle_and_input"`` (default) means the callable
            runs before the handler and its return value is injected;
            ``"guard"`` means the callable is a security check that
            may raise to deny access.  A single dependency can have
            both roles (guard + input provider).
        description: Human-readable description.
    """

    inject_fqn: str | tuple[str, ...]
    callable_arg: int = 0
    scope: str = "lifecycle_and_input"
    description: str = ""


# --- EP-7: Dispatch resolution ---


@dataclass(frozen=True)
class DispatchPattern:
    """Declares a framework dispatch pattern the call graph misses.

    ``invocation_scope`` keeps registration and invocation semantics in the
    provider declaration instead of baking framework-specific knowledge into
    conversion:

    - ``"registration_caller"``: the callback is invoked as a consequence of
      the matched call site, so the registration call's caller is the synthetic
      caller (e.g. background task scheduling).
    - ``"matching_emission"``: the match registers a callback keyed by
      ``invocation_key``; a separate ``"emission_caller"`` match supplies the
      runtime caller.
    - ``"emission_caller"``: the matched call emits callbacks registered under
      ``invocation_key``.
    - ``"framework_lifecycle"``: the framework invokes the registered callback
      during the declared ``hook_type``; route full-stack construction treats
      the callback as a lifecycle hook rather than inventing a user-code caller.
    """

    source_fqn: str | tuple[str, ...]
    target_method_names: tuple[str, ...]
    dispatch_type: str  # "method_view", "signal", "url_dispatch"
    callback_arg: int | None = 0
    callback_kwarg: str | None = None
    invocation_scope: str = "registration_caller"
    invocation_key: str | None = None
    hook_type: HookType | None = None
    description: str = ""


# --- EP-8: Flow propagation ---


@dataclass(frozen=True)
class FlowPropagatorPattern:
    """Declares how data flows through a library call.

    The flow tracer uses these during BFS to follow data through
    calls that are opaque to structural analysis.

    Matched by ``fqn`` **and/or** bare method ``names``.  ``names`` is the
    receiver-type-independent escape hatch (mirroring :class:`EffectCallPattern`
    / :class:`ClaimContainerPattern` / :class:`ValidatedValueGuardPattern`): a
    call whose bare method name matches propagates even when its receiver type
    cannot be resolved.  This closes a token-flow false negative for clients
    obtained from a registry call whose return type the index cannot resolve —
    e.g. ``oauth.<provider>.authorize_access_token()`` from
    ``oauth.register(...)`` — where the concrete-FQN and receiver-type paths
    both miss the propagating call.  Use it only for federation-/library-
    specific method names distinctive enough that a bare-name match is sound;
    do NOT use it for generic names (``get``, ``decode``) where bare-name
    matching would over-propagate.

    Attributes:
        fqn: Canonical FQN(s) of the propagating call.
        names: Bare method names to match receiver-type-independently.
    """

    fqn: str | tuple[str, ...]
    input_arg: int | None  # positional argument that carries tainted data in
    output: str  # "return" | "receiver" | "arg:N" | "kwarg:name"
    input_keyword: str | None = None  # keyword argument that carries tainted data in
    input_required: bool = True  # False when a no-input call has no data to propagate
    input_variadic: bool = False  # True when every non-excluded argument carries data
    excluded_input_args: tuple[int, ...] = ()
    excluded_input_keywords: tuple[str, ...] = ()
    names: tuple[str, ...] = ()  # bare method names matched receiver-type-independently
    description: str = ""


# --- EP-8a: Provider-generated safe values ---


@dataclass(frozen=True)
class SafeGeneratedURLPattern:
    """Declares that a call return is a provider-generated URL.

    The returned value may still contain user-derived path/query data, but
    providers can mark it safe for sink kinds where the framework controls the
    destination boundary, such as Flask ``url_for()`` for open redirects.
    """

    fqn: str | tuple[str, ...]
    output: str = "return"
    safe_for_sink_kinds: tuple[str, ...] = ("OPEN_REDIRECT",)
    external_kwarg: str | None = None
    external_safe: bool = False
    description: str = ""


# --- EP-8b: Validated value guards ---


@dataclass(frozen=True)
class ValidatedValueGuardPattern:
    """Declares that a guard call validates one argument for sink kinds.

    This covers project-local validators such as ``is_safe_url(target)`` where
    the call returns a boolean and the guarded branch can safely use the same
    value in selected sink kinds.  The descriptor is generic; providers decide
    which FQNs or simple names have that contract.
    """

    fqn: str | tuple[str, ...] | None = None
    names: tuple[str, ...] = ()
    arg: int | None = 0
    keyword: str | None = None
    safe_for_sink_kinds: tuple[str, ...] = ("OPEN_REDIRECT",)
    validated_when: bool = True
    category: str = "VALIDATION"
    description: str = ""


# --- EP-8c: Taint sinks (injection vectors) ---


@dataclass(frozen=True)
class TaintSinkPattern:
    """Declares a function argument as an injection sink.

    If user-controlled input flows to this argument, it's a finding.
    """

    fqn: str | tuple[str, ...]
    arg: int | None  # which positional arg is the sink
    sink_kind: str  # "SQL_INJECTION", "SSTI", "PATH_TRAVERSAL", etc.
    keyword: str | None = None  # keyword name for the sink argument
    when: WhenPredicate | None = None  # e.g. only when arg is NOT a literal
    description: str = ""


# --- EP-10: State proxy declarations ---


@dataclass(frozen=True)
class StateProxyPattern:
    """Declares that an FQN is a proxy that resolves to scoped state.

    Matches ``flask_login.current_user`` -> ``g._login_user``.
    """

    fqn: str | tuple[str, ...]
    resolves_to: str | tuple[str, ...]  # e.g. "flask.g._login_user"
    scope: str  # "REQUEST" | "SESSION" | "SERVER"
    description: str = ""


# =====================================================================
# Provider base class
# =====================================================================


class Provider:
    """Base class for semantic layer providers.

    Subclass and populate class attributes with descriptor tuples.
    Override ``extract_*`` methods only for patterns that cannot be
    expressed declaratively.

    Minimal example (flask-login)::

        class FlaskLoginProvider(Provider):
            meta = ProviderMeta(
                id="flask-login",
                name="Flask-Login",
                library="Flask-Login",
                library_fqn="flask_login",
            )

            checks = (
                SecurityCheckPattern(
                    fqn="flask_login.login_required",
                    kind=CheckKind.DECORATOR,
                    category="AUTHENTICATION",
                ),
            )

    All tuple attributes are optional.  Omit any category your
    provider doesn't contribute to.

    The engine processes providers in declared order.  Later providers
    can override earlier ones when they share ``meta.id``.
    """

    # -- Metadata (required) --
    meta: ProviderMeta

    # -- FQN alias map (optional) --

    fqn_aliases: ClassVar[dict[str, str]] = {}
    """Module-level FQN alias map for re-export resolution.

    Maps internal/alternative FQN prefixes to the canonical prefix.
    The engine applies these before pattern matching, so providers
    can declare patterns using canonical FQNs only.

    Example::

        fqn_aliases = {
            "flask_login.utils": "flask_login",
            "flask_login.login_manager": "flask_login",
        }

    This means ``flask_login.utils.login_required`` is matched as
    ``flask_login.login_required``, eliminating duplicate entries.
    """

    # -- Declarative descriptors (all optional) --

    routes: tuple[
        RouteDecorator | RouteCallPattern | ClassViewPattern | ImperativeRoutePattern, ...
    ] = ()
    """Route registration patterns this provider recognizes."""

    router_groups: tuple[RouterGroupPattern, ...] = ()
    """Router group constructor patterns (named route-group namespaces)."""

    router_group_mounts: tuple[RouterGroupMountPattern, ...] = ()
    """Router group mount patterns (attaching groups to apps/parents)."""

    inputs: tuple[
        InputAttributePattern
        | InputContainerPattern
        | InputMethodPattern
        | InputFieldAccessPattern
        | InputParameterPattern
        | ClaimContainerPattern,
        ...,
    ] = ()
    """Request input access patterns."""

    effects: tuple[EffectCallPattern | EffectAttributePattern | EffectSubscriptPattern, ...] = ()
    """Side-effect producing call/attribute/subscript patterns."""

    checks: tuple[SecurityCheckPattern | ClassAttributeGuardPattern, ...] = ()
    """Security check decorators, function calls, and class-attribute guards."""

    lifecycle: tuple[
        LifecycleDecoratorPattern
        | LifecycleRegistrationPattern
        | CheckRegistrationPattern
        | ControlPlaneExemptionPattern
        | MiddlewareClassPattern,
        ...,
    ] = ()
    """Lifecycle hook registration and middleware class patterns."""

    dependencies: tuple[DependencyPattern, ...] = ()
    """Dependency injection patterns (FastAPI Depends, Litestar Provide, etc.)."""

    dispatches: tuple[DispatchPattern, ...] = ()
    """Framework dispatch patterns the L1 call graph misses."""

    propagators: tuple[FlowPropagatorPattern, ...] = ()
    """Data flow propagation rules through library calls."""

    safe_generated_urls: tuple[SafeGeneratedURLPattern, ...] = ()
    """Provider-generated URL values safe for specific sink kinds."""

    validation_guards: tuple[ValidatedValueGuardPattern, ...] = ()
    """Guard calls that validate an existing value for specific sink kinds."""

    sinks: tuple[TaintSinkPattern, ...] = ()
    """Injection sink declarations."""

    proxies: tuple[StateProxyPattern, ...] = ()
    """State proxy aliases (e.g. current_user -> g._login_user)."""

    # -- Extraction hooks (override for complex patterns) --
    #
    # These receive the full CodeIndex and return domain objects.
    # Use ONLY when declarative descriptors can't express the pattern.
    # The engine calls these AFTER processing all declarative descriptors.
    #
    # def extract_routes(self, idx: CodeIndex) -> Sequence[Route]: ...
    # def extract_effects(self, idx: CodeIndex) -> Sequence[Effect]: ...
    # def extract_inputs(self, idx: CodeIndex, routes: Sequence[Route]) -> Sequence[InputRead]: ...
    # etc.
