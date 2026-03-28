"""Infer custom auth checks from structural and call-graph signals.

Two families of project-specific auth enforcement that providers cannot
declare statically, both surfaced as ``ConcreteCondition`` objects merged
into the standard ``conditions_by_function`` dict so they become visible
through the existing ``scope.checks()`` API:

**Custom auth decorators** (DISC-090) — the engine's biggest decorator-level
FP driver (~240 false positives) was its inability to recognize
project-specific decorators like ``@authed_only``, ``@admins_only``,
``@require_permission("admin")``.  Two-pass:
  Pass 1 — **Call-graph tracing** (high confidence): a decorator's inner
    function calls ``abort(401/403)``, redirects to a login URL, or
    delegates to a known auth check.
  Pass 2 — **Name heuristic** (moderate confidence): the decorator's name
    matches auth-suggestive patterns AND its definition is a closure
    factory with at least one condition branch.

**In-body authorization guards** (FLAW-127) — authorization written in the
handler body rather than a decorator (``if not current_user.is_admin:
abort(403)``).  ``scope.checks()`` only ever saw provider/decorator checks,
so a coverage rule labelled such routes "AUTHENTICATION only, missing AUTHORIZATION" —
226 false positives on one real-world corpus, the single largest FP source.
A branch condition that tests a recognized role/permission/identity
attribute of the principal (``current_user.is_admin`` / ``.role`` /
``.is_authenticated``) is recognized as a guard regardless of how the
failing branch denies access — real apps use ``abort(403)``,
``return ..., 403``, redirects, and more (some real apps deny via ``return``,
not ``abort``).  A bare/ambiguous principal test additionally requires the
function to perform an explicit denial (``abort(401/403)``, login redirect,
``Forbidden``/``Unauthorized``), which also supplies its category.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from flawed._semantic._check_conversion import ConcreteCondition
from flawed._semantic._conversion_utils import location
from flawed.conditions import ConditionKind, DenialKind, GuardClassification
from flawed.core import AnalysisGap, GapKind, Provenance

if TYPE_CHECKING:
    from collections.abc import Mapping

    from flawed._index import CodeIndex
    from flawed._index._types import CallEdge, DecoratorFact, FunctionRecord, SourceSpan
    from flawed.function import Function

# -- Constants ----------------------------------------------------------------

_AUTH_NAME_RE = re.compile(
    r"(?:^|_)("
    r"auth|authed|login|admin|admins|permission|permissions|require|required"
    r"|restrict|restricted|protect|protected|guard|guarded"
    r"|verified|registered|roles"
    r")(?:_|$|s$)",
    re.IGNORECASE,
)

_ABORT_AUTH_CODES = frozenset({401, 403})

# Known auth-related callee FQNs that, when called from a decorator's
# inner function, signal the decorator enforces auth.
_KNOWN_AUTH_CALLEES = frozenset(
    {
        "flask_login.login_required",
        "flask_login.utils.login_required",
        "flask.abort",
        "werkzeug.exceptions.abort",
        "builtins.abort",
    }
)

_L2_INFERRED_PROVENANCE_CALLGRAPH = Provenance(
    source_layer="L2",
    interpreter="custom_auth_inference",
    confidence=0.90,
    supporting_facts=("call-graph tracing: decorator inner calls abort/redirect/known-auth",),
)

_L2_INFERRED_PROVENANCE_NAME = Provenance(
    source_layer="L2",
    interpreter="custom_auth_inference",
    confidence=0.75,
    supporting_facts=("name heuristic: auth-suggestive name + closure factory structure",),
)

_L2_INFERRED_PROVENANCE_INBODY = Provenance(
    source_layer="L2",
    interpreter="inbody_guard_inference",
    confidence=0.85,
    supporting_facts=(
        "branch condition tests a security principal and the function performs an auth denial",
    ),
)

# Security-principal bases: an attribute/comparison rooted at one of these is a
# guard over the *request principal*, not an arbitrary resource object.
_PRINCIPAL_BASE_RE = re.compile(
    r"\b(?:current_user|session)\b|\bg\.(?:user|identity|current_user)\b|\brequest\.user\b"
)
# Principal attributes that denote an authorization decision (role/permission).
_AUTHZ_ATTR_RE = re.compile(
    r"\b(?:is_admin|is_administrator|is_superuser|is_staff|is_moderator|is_owner"
    r"|role|roles|permission|permissions|has_role|has_roles|has_permission"
    r"|has_permissions|can_\w+)\b",
    re.IGNORECASE,
)
# Principal attributes that denote an authentication decision (identity/session).
_AUTHN_ATTR_RE = re.compile(
    r"\b(?:is_authenticated|is_anonymous|logged_in|is_active)\b",
    re.IGNORECASE,
)


# -- Data types ---------------------------------------------------------------


@dataclass(frozen=True)
class InferredAuthCheck:
    """A decorator inferred to be an auth guard."""

    decorator_fqn: str
    category: str
    confidence: float
    reason: str


@dataclass(frozen=True)
class AuthInferenceResult:
    """Result of custom auth inference for one codebase."""

    conditions_by_function: dict[str, list[ConcreteCondition]]
    gaps: tuple[AnalysisGap, ...]
    inferred_checks: tuple[InferredAuthCheck, ...]


# -- Public API ---------------------------------------------------------------


def infer_custom_auth_checks(
    idx: CodeIndex,
    functions_by_fqn: Mapping[str, Function],
    matched_check_fqns: frozenset[str],
    known_auth_fqns: frozenset[str],
) -> AuthInferenceResult:
    """Infer custom auth decorators from structural and call-graph signals.

    Args:
        idx: Layer 1 code index.
        functions_by_fqn: Enriched L2 function objects by FQN.
        matched_check_fqns: FQNs already matched by provider check patterns.
        known_auth_fqns: FQNs of known auth-related callees from providers.

    Returns:
        AuthInferenceResult with inferred conditions and gaps.
    """
    l1_fns = {fn.fqn: fn for fn in idx.functions}
    conditions_by_function: dict[str, list[ConcreteCondition]] = {}
    gaps: list[AnalysisGap] = []
    inferred: list[InferredAuthCheck] = []
    seen_decorator_fqns: set[str] = set()

    all_known_auth = known_auth_fqns | _KNOWN_AUTH_CALLEES

    for dec in idx.decorators:
        if dec.fqn is None:
            continue
        if dec.fqn in matched_check_fqns:
            continue
        if dec.fqn in seen_decorator_fqns:
            # Already inferred for this decorator FQN — just apply result.
            _apply_existing_inference(
                dec,
                inferred,
                functions_by_fqn,
                conditions_by_function,
            )
            continue

        results = _analyze_decorator(dec, idx, l1_fns, all_known_auth)
        if results:
            seen_decorator_fqns.add(dec.fqn)
            inferred.extend(results)
            for check in results:
                _apply_inference(
                    dec,
                    check,
                    functions_by_fqn,
                    conditions_by_function,
                )
        elif _name_is_auth_suggestive(dec.name):
            # No signal — record gap when name looks auth-ish but
            # call-graph/structural analysis couldn't confirm.
            gaps.append(
                AnalysisGap(
                    kind=GapKind.INFERENCE_FAILURE,
                    message=(
                        f"Decorator @{dec.name} ({dec.fqn}) has an auth-suggestive "
                        f"name but could not be confirmed as an auth guard"
                    ),
                    affected_file=dec.location.file,
                    affected_function=dec.target_fqn,
                    source_error="custom_auth_inference: insufficient signal",
                    origin_phase="custom_auth_inference",
                )
            )

    # In-body authorization guards (FLAW-127): authorization enforced in the
    # handler body rather than via a decorator.  Merged into the same dict so
    # they surface through scope.checks() exactly like decorator-level checks.
    for fqn, inbody_conditions in _infer_inbody_guard_conditions(idx, functions_by_fqn).items():
        conditions_by_function.setdefault(fqn, []).extend(inbody_conditions)

    return AuthInferenceResult(
        conditions_by_function=conditions_by_function,
        gaps=tuple(gaps),
        inferred_checks=tuple(inferred),
    )


# -- In-body guard inference (FLAW-127) ---------------------------------------


def _infer_inbody_guard_conditions(
    idx: CodeIndex,
    functions_by_fqn: Mapping[str, Function],
) -> dict[str, list[ConcreteCondition]]:
    """Infer in-body authz/authn guards as security checks.

    A branch condition that tests a recognized role/permission/identity
    attribute of the request principal (``current_user.is_admin``,
    ``current_user.role``, ``current_user.is_authenticated``) is itself the
    authorization/authentication signal — independent of how the failing
    branch denies access (``abort(403)``, ``return jsonify(...), 403``,
    ``flash`` + redirect, ...).  This matters because real apps deny in many
    ways; e.g. some real apps use ``return ..., 403`` rather than ``abort``.

    An *ambiguous* principal test (bare ``if not current_user:`` /
    ``if session.get("user_id"):`` with no recognized attribute) is only
    treated as a guard when the function performs an explicit auth denial
    (``abort(401/403)``, login redirect, ``Forbidden``/``Unauthorized``), and
    the category is taken from the denial's HTTP semantics.  This keeps
    non-security branches and cosmetic reads from being counted as checks.
    """
    out: dict[str, list[ConcreteCondition]] = {}
    for fqn, function in functions_by_fqn.items():
        cfg = idx.cfg(fqn)
        if cfg is None:
            continue
        has_denial, denial_category = _function_auth_denial(idx, fqn)
        seen: set[tuple[str, int, int]] = set()
        for block in cfg.blocks:
            expression = block.condition_expr
            condition_location = block.condition_location
            if expression is None or condition_location is None:
                continue
            key = (expression, condition_location.line, condition_location.column)
            if key in seen:
                continue
            seen.add(key)
            category = _inbody_guard_category(expression, has_denial, denial_category)
            if category is None:
                continue
            out.setdefault(fqn, []).append(
                _make_inbody_condition(expression, condition_location, function, category)
            )
    return out


def _function_auth_denial(idx: CodeIndex, fqn: str) -> tuple[bool, str | None]:
    """Return whether *fqn* performs an auth denial and the implied category.

    The category hint follows HTTP semantics — ``abort(403)`` / ``Forbidden``
    imply AUTHORIZATION, ``abort(401)`` / login redirect / ``Unauthorized``
    imply AUTHENTICATION — and is used only when the guarded attribute itself
    is ambiguous.
    """
    saw_authz = False
    saw_authn = False
    for edge in idx.call_graph.edges_from(fqn):
        if _is_abort_call(edge):
            code = _abort_code(edge)
            if code == 403:
                saw_authz = True
            elif code == 401:
                saw_authn = True
            else:
                saw_authn = True
        elif _is_login_redirect(edge):
            saw_authn = True
        elif _is_forbidden_denial(edge):
            saw_authz = True
        elif _is_unauthorized_denial(edge):
            saw_authn = True
    if not (saw_authz or saw_authn):
        return False, None
    return True, "AUTHORIZATION" if saw_authz else "AUTHENTICATION"


def _is_forbidden_denial(edge: CallEdge) -> bool:
    """Call to a ``Forbidden`` (HTTP 403) exception/handler → authorization denial."""
    return edge.callee_fqn is not None and edge.callee_fqn.endswith("Forbidden")


def _is_unauthorized_denial(edge: CallEdge) -> bool:
    """Call to an ``Unauthorized`` (HTTP 401) exception/handler → authentication denial."""
    return edge.callee_fqn is not None and edge.callee_fqn.endswith("Unauthorized")


def _inbody_guard_category(
    expression: str,
    has_denial: bool,
    denial_category: str | None,
) -> str | None:
    """Categorize a branch condition as an in-body guard, or ``None`` if it isn't one.

    A recognized role/permission attribute → AUTHORIZATION; a recognized
    identity attribute → AUTHENTICATION; both regardless of the denial form.
    An ambiguous principal test qualifies only when the function denies access,
    taking its category from the denial's HTTP semantics.
    """
    if _PRINCIPAL_BASE_RE.search(expression) is None:
        return None
    if _AUTHZ_ATTR_RE.search(expression) is not None:
        return "AUTHORIZATION"
    if _AUTHN_ATTR_RE.search(expression) is not None:
        return "AUTHENTICATION"
    # Ambiguous principal test (bare current_user / session): a guard only when
    # the function actually denies access.
    if has_denial:
        return denial_category
    return None


def _inbody_condition_kind(expression: str) -> ConditionKind:
    if any(op in expression for op in ("==", "!=", "<", ">")):
        return ConditionKind.COMPARISON
    if " not in " in expression or " in " in expression:
        return ConditionKind.MEMBERSHIP
    if " is " in expression:
        return ConditionKind.IDENTITY
    return ConditionKind.TRUTHINESS


def _make_inbody_condition(
    expression: str,
    span: SourceSpan,
    function: Function,
    category: str,
) -> ConcreteCondition:
    """Build a categorized ``ConcreteCondition`` for an in-body guard."""
    from flawed._semantic._scope import ConcreteCodeScope

    empty = ConcreteCodeScope()
    return ConcreteCondition(
        expression=expression,
        location=location(span),
        function=function,
        kind=_inbody_condition_kind(expression),
        provenance=_L2_INFERRED_PROVENANCE_INBODY,
        category=category,
        provider_id=None,
        _true_branch=empty,
        _false_branch=empty,
        _guard=GuardClassification(
            guarded_branch=empty,
            denied_branch=empty,
            denial_kind=DenialKind.ABORT,
            confidence=0.85,
        ),
    )


# -- Analysis passes ----------------------------------------------------------


def _analyze_decorator(
    dec: DecoratorFact,
    idx: CodeIndex,
    l1_fns: dict[str, FunctionRecord],
    known_auth_fqns: frozenset[str],
) -> list[InferredAuthCheck]:
    """Two-pass analysis: call-graph first, name heuristic as fallback.

    Returns potentially multiple checks — one per distinct auth category the
    decorator enforces (a single guard is commonly both AUTHENTICATION and
    AUTHORIZATION) — or an empty list when no signal is found.
    """
    assert dec.fqn is not None
    # Pass 1: Call-graph tracing
    result = _pass1_call_graph(dec, idx, l1_fns, known_auth_fqns)
    if result:
        return result

    # Pass 2: Name + structural heuristic
    return _pass2_name_heuristic(dec, idx, l1_fns)


def _pass1_call_graph(
    dec: DecoratorFact,
    idx: CodeIndex,
    l1_fns: dict[str, FunctionRecord],
    known_auth_fqns: frozenset[str],
) -> list[InferredAuthCheck]:
    """Analyze call graph from decorator's implementation for auth signals.

    Returns one ``InferredAuthCheck`` per distinct category the decorator
    enforces (a guard can be both AUTHENTICATION and AUTHORIZATION), or an
    empty list when no auth signal is found.
    """
    assert dec.fqn is not None
    # Find the decorator definition function and its nested wrappers.
    wrapper_fqns = _decorator_wrapper_fqns(dec.fqn, l1_fns)
    if not wrapper_fqns:
        # No nested functions — the decorator itself might be the wrapper.
        # Check calls from the decorator function directly.
        wrapper_fqns = [dec.fqn]

    by_category: dict[str, _AuthSignal] = {}
    for wrapper_fqn in wrapper_fqns:
        edges = idx.call_graph.edges_from(wrapper_fqn)
        for signal in _classify_call_edges(edges, known_auth_fqns):
            by_category.setdefault(signal.category, signal)

    return [
        InferredAuthCheck(
            decorator_fqn=dec.fqn,
            category=signal.category,
            confidence=0.90,
            reason=signal.reason,
        )
        for signal in by_category.values()
    ]


def _pass2_name_heuristic(
    dec: DecoratorFact,
    _idx: CodeIndex,
    l1_fns: dict[str, FunctionRecord],
) -> list[InferredAuthCheck]:
    """Name pattern + closure factory structure → moderate confidence."""
    if not _name_is_auth_suggestive(dec.name):
        return []

    assert dec.fqn is not None
    # Must be a closure factory: has at least one nested function.
    nested = _decorator_wrapper_fqns(dec.fqn, l1_fns)
    if not nested:
        return []

    # Determine category from name.
    category = _category_from_name(dec.name)
    return [
        InferredAuthCheck(
            decorator_fqn=dec.fqn,
            category=category,
            confidence=0.75,
            reason=f"name_pattern ({dec.name}) + closure_factory",
        )
    ]


# -- Helper functions ---------------------------------------------------------


@dataclass(frozen=True)
class _AuthSignal:
    category: str
    reason: str


def _classify_call_edges(
    edges: tuple[CallEdge, ...],
    known_auth_fqns: frozenset[str],
) -> list[_AuthSignal]:
    """Collect every auth category the call edges enforce.

    A single decorator commonly enforces BOTH categories — e.g. an
    ``admins_only``-style guard that ``abort(403)``s non-admins (AUTHORIZATION) *and* redirects
    anonymous users to login (AUTHENTICATION).  Returning only the first match
    (the historical behaviour) dropped the second category, so a coverage rule
    needing the dropped one (e.g. a SESSION write needs AUTHENTICATION) then
    false-flagged an already-guarded route.  We therefore accumulate all
    distinct categories — first reason per category wins — instead of
    short-circuiting on the first edge.
    """
    by_category: dict[str, _AuthSignal] = {}
    for edge in edges:
        if edge.callee_fqn is None:
            continue

        # abort(401/403) -> AUTHENTICATION / AUTHORIZATION by HTTP semantics
        if _is_abort_call(edge):
            code = _abort_code(edge)
            if code in _ABORT_AUTH_CODES:
                category = "AUTHORIZATION" if code == 403 else "AUTHENTICATION"
                by_category.setdefault(
                    category, _AuthSignal(category, f"call_graph: calls abort({code})")
                )

        # redirect to a login-like URL -> AUTHENTICATION
        if _is_login_redirect(edge):
            by_category.setdefault(
                "AUTHENTICATION",
                _AuthSignal("AUTHENTICATION", "call_graph: redirects to login"),
            )

        # delegation to a known auth check -> AUTHENTICATION
        if edge.callee_fqn in known_auth_fqns:
            by_category.setdefault(
                "AUTHENTICATION",
                _AuthSignal("AUTHENTICATION", f"call_graph: delegates to {edge.callee_fqn}"),
            )

    return list(by_category.values())


def _is_abort_call(edge: CallEdge) -> bool:
    """Check if edge is a call to abort/flask.abort/werkzeug.exceptions.abort."""
    if edge.callee_fqn is None:
        return False
    callee = edge.callee_fqn
    return callee in {"flask.abort", "werkzeug.exceptions.abort"} or callee.endswith(".abort")


def _abort_code(edge: CallEdge) -> int | None:
    """Extract the HTTP status code from an abort() call."""
    if not edge.arguments:
        return None
    first_arg = edge.arguments[0]
    try:
        return int(first_arg.expression)
    except (ValueError, TypeError):
        return None


def _is_login_redirect(edge: CallEdge) -> bool:
    """Check if edge is a redirect to a login-like URL."""
    if edge.callee_fqn is None:
        return False
    if not edge.callee_fqn.endswith(("redirect", "flask.redirect")):
        return False
    # Check if any argument references "login" (url_for("auth.login") etc.)
    return any("login" in arg.expression.lower() for arg in edge.arguments)


def _name_is_auth_suggestive(name: str) -> bool:
    """Check if a decorator name suggests auth enforcement."""
    return _AUTH_NAME_RE.search(name) is not None


def _category_from_name(name: str) -> str:
    """Infer auth category from decorator name."""
    lower = name.lower()
    if any(kw in lower for kw in ("admin", "permission", "role", "restrict", "authz")):
        return "AUTHORIZATION"
    return "AUTHENTICATION"


def _decorator_wrapper_fqns(
    decorator_fqn: str,
    l1_fns: dict[str, FunctionRecord],
) -> list[str]:
    """Find nested function FQNs inside a decorator definition."""
    return [fn.fqn for fn in l1_fns.values() if fn.parent_function == decorator_fqn]


def _apply_inference(
    dec: DecoratorFact,
    check: InferredAuthCheck,
    functions_by_fqn: Mapping[str, Function],
    conditions_by_function: dict[str, list[ConcreteCondition]],
) -> None:
    """Create a ConcreteCondition from an inferred auth check and attach it."""
    function = functions_by_fqn.get(dec.target_fqn)
    if function is None:
        # May be a class — find all methods.
        for fn in functions_by_fqn.values():
            if fn.parent_class == dec.target_fqn:
                condition = _make_condition(dec, check, fn)
                conditions_by_function.setdefault(fn.fqn, []).append(condition)
        return

    condition = _make_condition(dec, check, function)
    conditions_by_function.setdefault(function.fqn, []).append(condition)


def _apply_existing_inference(
    dec: DecoratorFact,
    all_inferred: list[InferredAuthCheck],
    functions_by_fqn: Mapping[str, Function],
    conditions_by_function: dict[str, list[ConcreteCondition]],
) -> None:
    """Reuse an existing inference for a different application of the same decorator.

    A decorator may have produced several inferred checks (one per auth
    category); apply *all* of them, not just the first.
    """
    for check in all_inferred:
        if check.decorator_fqn == dec.fqn:
            _apply_inference(dec, check, functions_by_fqn, conditions_by_function)


def _make_condition(
    dec: DecoratorFact,
    check: InferredAuthCheck,
    function: Function,
) -> ConcreteCondition:
    """Build a ConcreteCondition from a decorator fact and inference result."""
    from flawed._semantic._scope import ConcreteCodeScope

    provenance = (
        _L2_INFERRED_PROVENANCE_CALLGRAPH
        if check.confidence >= 0.85
        else _L2_INFERRED_PROVENANCE_NAME
    )
    empty = ConcreteCodeScope()
    return ConcreteCondition(
        expression=f"@{dec.name}",
        location=location(dec.location),
        function=function,
        kind=ConditionKind.CALL_RESULT,
        provenance=provenance,
        category=check.category,
        provider_id=None,
        _true_branch=empty,
        _false_branch=empty,
        _guard=GuardClassification(
            guarded_branch=empty,
            denied_branch=empty,
            denial_kind=DenialKind.ABORT if check.confidence >= 0.85 else DenialKind.UNKNOWN,
            confidence=check.confidence,
        ),
    )
