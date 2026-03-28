"""Concrete scope query surfaces backed by Layer 2 observations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from flawed._semantic._cfgview import ControlFlowView
from flawed._semantic._collections import (
    ConcreteCallSiteCollection,
    ConcreteConditionCollection,
    ConcreteDecoratorCollection,
    ConcreteEffectCollection,
    ConcreteFunctionCollection,
    ConcreteInputReadCollection,
    ConcretePredicateCollection,
    ConcreteSafeGeneratedURLCollection,
    ConcreteTaintSinkCollection,
    ConcreteValidatedValueCollection,
)
from flawed.effects import EffectCategory

if TYPE_CHECKING:
    from flawed.calls import CallSite, FnSelector
    from flawed.conditions import DenialKind, ExceptionGuard, SwallowedRejection
    from flawed.core import AnalysisGap
    from flawed.disagreement import TypeDisagreement
    from flawed.effects import Effect, EffectSelector
    from flawed.flow import ValueHandle
    from flawed.function import Decorator, Function
    from flawed.generated import SafeGeneratedURL
    from flawed.inputs import InputRead, InputSource
    from flawed.route import HttpMethod
    from flawed.sinks import TaintSink
    from flawed.validation import ValidatedValue


def dedupe_gaps(gaps: tuple[AnalysisGap, ...]) -> tuple[AnalysisGap, ...]:
    """Remove duplicate analysis gaps by identity key.

    Uses (kind, message, affected_file, affected_function, source_error)
    as the deduplication key.  Preserves insertion order.
    """
    result: list[AnalysisGap] = []
    seen: set[tuple[object, ...]] = set()
    for gap in gaps:
        key = (
            gap.kind,
            gap.message,
            gap.affected_file,
            gap.affected_function,
            gap.source_error,
        )
        if key in seen:
            continue
        seen.add(key)
        result.append(gap)
    return tuple(result)


class ConcreteCodeScope:
    """Concrete partial implementation of the Rule API ``CodeScope`` surface.

    Supports input reads, effects, and call-site queries for function bodies.
    """

    __slots__ = (
        "_call_sites",
        "_cfg",
        "_conditions",
        "_decorators",
        "_effects",
        "_functions",
        "_gaps",
        "_input_reads",
        "_method_branches",
        "_predicates",
        "_safe_generated_urls",
        "_sinks",
        "_type_disagreements",
        "_validated_values",
    )

    def __init__(
        self,
        *,
        input_reads: tuple[InputRead, ...] = (),
        effects: tuple[Effect, ...] = (),
        sinks: tuple[TaintSink, ...] = (),
        safe_generated_urls: tuple[SafeGeneratedURL, ...] = (),
        validated_values: tuple[ValidatedValue, ...] = (),
        type_disagreements: tuple[TypeDisagreement, ...] = (),
        call_sites: tuple[CallSite, ...] = (),
        conditions: tuple[object, ...] = (),
        predicates: tuple[object, ...] = (),
        decorators: tuple[Decorator, ...] = (),
        gaps: tuple[AnalysisGap, ...] = (),
        cfg: ControlFlowView | None = None,
        method_branches: dict[HttpMethod, ConcreteCodeScope] | None = None,
        functions: tuple[Function, ...] = (),
    ) -> None:
        self._functions = functions
        self._input_reads = input_reads
        self._effects = effects
        self._sinks = sinks
        self._safe_generated_urls = safe_generated_urls
        self._validated_values = validated_values
        self._type_disagreements = type_disagreements
        self._call_sites = call_sites
        self._conditions = conditions
        self._predicates = predicates
        self._decorators = decorators
        self._gaps = gaps
        self._cfg = cfg or ControlFlowView.unavailable(gaps=gaps)
        self._method_branches = method_branches or {}

    def conditions(self) -> ConcreteConditionCollection:
        """All conditional expressions in this scope."""
        return ConcreteConditionCollection(self._conditions)

    def predicates(self) -> ConcretePredicateCollection:
        """Predicate expressions produced as values in this scope."""
        return ConcretePredicateCollection(self._predicates)

    def conditions_using(self, value: ValueHandle) -> ConcreteConditionCollection:
        """Conditions that reference the given value."""
        return self.conditions().using(value)

    def checks(self, category: str | None = None) -> ConcreteConditionCollection:
        """Provider-declared security checks in this scope."""
        return self.conditions().where(lambda condition: _is_security_check(condition, category))

    def reads(self, source: InputSource | None = None) -> ConcreteInputReadCollection:
        """Input reads in this scope, optionally filtered by source.

        The no-argument (wildcard) form deliberately EXCLUDES identifier /
        auth-subject sources (session values, framework globals — anything whose
        :attr:`~flawed.inputs.InputSource.is_identity_source` is true). These are
        usually trusted state, so flooding them into the stream every
        attacker-input rule consumes would cause a corpus-wide false-positive
        surge (FLAW-230/240); a rule that wants them asks explicitly via
        ``reads(SessionValue())``. Passing an explicit source bypasses the
        containment, so the opt-in path still sees identity reads.
        """
        if source is None:
            visible = tuple(
                read for read in self._input_reads if not read.source.is_identity_source
            )
            return ConcreteInputReadCollection(visible)
        return ConcreteInputReadCollection(self._input_reads).from_source(source)

    def reads_flowing_to(self, target: ValueHandle) -> ConcreteInputReadCollection:
        """Reads in this scope whose value flows to *target*.

        The correlation comparative/invariant-flow rules otherwise hand-roll
        this filter (FLAW-199). It is evaluated over the FULL identity-inclusive
        read set, so it is a deliberate SUPERSET of
        ``[r for r in scope.reads() if r.value.flows_to(target)]``: identity
        sources (session values, framework globals) are excluded from the noisy
        wildcard ``reads()`` stream for FP containment (FLAW-240) but remain
        visible to this *targeted* query, so a session-vs-request inconsistency can
        still be paired. Reads are evaluated and returned in scope order so
        evidence selection is stable. ``flows_to`` already memoises per
        (source, target) for the scan, so repeated queries reuse work.
        """
        feeding = tuple(read for read in self._input_reads if read.value.flows_to(target))
        return ConcreteInputReadCollection(feeding)

    def effects(self, selector: EffectSelector | None = None) -> ConcreteEffectCollection:
        """Effects in this scope, optionally filtered by selector."""
        collection = ConcreteEffectCollection(self._effects)
        if selector is None:
            return collection
        return collection.matching(selector)

    def calls(self, selector: FnSelector | None = None) -> ConcreteCallSiteCollection:
        """Call sites matching the given function selector in this scope."""
        collection = ConcreteCallSiteCollection(self._call_sites)
        if selector is None:
            return collection
        return collection.to(selector)

    def reachable_functions(self) -> ConcreteFunctionCollection:
        """Functions whose bodies make up this scope.

        For a route/function ``reachable`` or ``full_stack`` scope this is the
        transitive call-graph closure (handler + every directly or indirectly
        called function, plus lifecycle hooks for ``full_stack``); for a
        ``body`` scope it is the single owning function.  The handler/owner is
        listed first, the rest in deterministic traversal order.  Replaces the
        hand-rolled ``.calls()``/``.target_fqn`` walk rule authors otherwise
        write to enumerate a route's code surface (FLAW-129).
        """
        return ConcreteFunctionCollection(self._functions)

    def sinks(self, kind: str | None = None) -> ConcreteTaintSinkCollection:
        """Taint sinks reached by input reads in this scope."""
        collection = ConcreteTaintSinkCollection(
            self._sinks,
            input_reads=self._input_reads,
            safe_generated_urls=self._safe_generated_urls,
            validated_values=self._validated_values,
            cfg=self._cfg,
        )
        if kind is None:
            return collection
        return collection.of_kind(kind)

    def validated_values(self) -> ConcreteValidatedValueCollection:
        """Validated values (input sanitization guards) in this scope."""
        return ConcreteValidatedValueCollection(self._validated_values)

    def generated_urls(self) -> ConcreteSafeGeneratedURLCollection:
        """Safe generated URLs (server-constructed redirect targets) in this scope."""
        return ConcreteSafeGeneratedURLCollection(self._safe_generated_urls)

    def decorators(self) -> ConcreteDecoratorCollection:
        """Decorators applied to functions in this scope."""
        return ConcreteDecoratorCollection(self._decorators)

    def type_disagreements(
        self,
        *,
        security_relevant: bool | None = None,
    ) -> tuple[TypeDisagreement, ...]:
        """Type-checker disagreement signals in this scope."""
        disagreements = self._type_disagreements
        if security_relevant is None:
            return disagreements
        return tuple(
            disagreement
            for disagreement in disagreements
            if disagreement.is_security_relevant is security_relevant
        )

    def exception_guards(self) -> tuple[ExceptionGuard, ...]:
        """Exception-based guards (try/except blocks acting as security checks)."""
        return _find_exception_guards(self._call_sites, self._cfg, effects=self._effects)

    def swallowed_rejections(self) -> tuple[SwallowedRejection, ...]:
        """Rejection ``raise``s swallowed by their ``except`` handler (FLAW-319)."""
        return _find_swallowed_rejections(self._call_sites, self._cfg, effects=self._effects)

    def branch(self, method: HttpMethod | str) -> ConcreteCodeScope | None:
        """Code scope for a reconstructed HTTP method branch, if present."""
        method_key = _coerce_method(method)
        if method_key is None:
            return None
        return self._method_branches.get(method_key)

    @property
    def gaps(self) -> tuple[AnalysisGap, ...]:
        """Analysis gaps affecting functions in this scope."""
        return self._gaps

    @property
    def cfg(self) -> ControlFlowView:
        """Control flow graph scoped to this code region."""
        return self._cfg


def _is_security_check(condition: object, category: str | None) -> bool:
    check_category = getattr(condition, "category", None)
    if not isinstance(check_category, str):
        return False
    if category is None or check_category == category:
        return True
    # A check may declare a COMPOUND category it satisfies on multiple axes, e.g.
    # flask_wtf validate_on_submit emits "CSRF|FORM_VALIDATION". Credit it to each
    # component so single-category coverage queries (e.g. CSRF, FORM_VALIDATION)
    # recognise it. FN-safe: a check only declares a component it genuinely provides.
    return category in check_category.split("|")


def _coerce_method(method: HttpMethod | str) -> HttpMethod | None:
    from flawed.route import HttpMethod

    if isinstance(method, HttpMethod):
        return method
    try:
        return HttpMethod(method.upper())
    except ValueError:
        return None


# =====================================================================
# Exception guard detection
# =====================================================================

# Denial indicators: generic call-target substrings that signal denial.
# Framework-specific FQN matching belongs in providers, not here.
_ABORT_INDICATORS = frozenset({"abort"})
_REDIRECT_INDICATORS = frozenset({"redirect"})
_RAISE_KEYWORDS = frozenset({"raise", "HTTPException", "Forbidden", "Unauthorized"})


@dataclass(frozen=True)
class _ExceptionRegionFacts:
    try_calls: tuple[CallSite, ...]
    try_effects: tuple[Effect, ...]
    handler_calls_by_block: dict[int, tuple[CallSite, ...]]
    handler_effects_by_block: dict[int, tuple[Effect, ...]]


def _find_exception_guards(
    call_sites: tuple[CallSite, ...],
    cfg_view: ControlFlowView,
    *,
    effects: tuple[Effect, ...] = (),
) -> tuple[ExceptionGuard, ...]:
    """Identify try/except blocks that act as security guards.

    A try/except is a guard when:
    - The try body contains at least one call (the "guarded call")
    - The except handler contains a denial action (abort, raise, redirect, error return)
    """
    from flawed.conditions import ExceptionGuard
    from flawed.core import Location, Provenance

    regions = cfg_view.try_regions
    if not regions or not call_sites:
        return ()

    guards: list[ExceptionGuard] = []

    for region in regions:
        try_block_ids = set(region.try_body_block_ids)
        handler_block_ids = {h.entry_block_id for h in region.handlers}
        facts = _exception_region_facts(
            call_sites,
            effects,
            cfg_view,
            try_block_ids=try_block_ids,
            handler_block_ids=handler_block_ids,
        )

        if not facts.try_calls:
            continue

        # For each handler, check if it contains a denial pattern
        for handler in region.handlers:
            handler_site_tuple = facts.handler_calls_by_block.get(handler.entry_block_id, ())
            handler_effect_tuple = facts.handler_effects_by_block.get(handler.entry_block_id, ())
            denial_kind = _classify_handler_denial(handler_site_tuple, handler_effect_tuple)
            if denial_kind is None:
                continue

            # Pick the last call in the try body as the guarded call
            # (most common pattern: the verification call is last before the handler)
            guarded_call = facts.try_calls[-1]

            location = Location(
                file=region.location.file,
                line=region.location.line,
                column=region.location.column,
                end_line=region.location.end_line,
                end_column=region.location.end_column,
            )

            # Build sub-scopes for try body and except body
            try_body_scope = ConcreteCodeScope(
                call_sites=facts.try_calls,
                effects=facts.try_effects,
                cfg=cfg_view.restricted_to(frozenset(try_block_ids)),
            )
            except_body_scope = ConcreteCodeScope(
                call_sites=handler_site_tuple,
                effects=handler_effect_tuple,
                cfg=cfg_view.restricted_to(frozenset({handler.entry_block_id})),
            )

            guards.append(
                ExceptionGuard(
                    try_body=try_body_scope,
                    except_body=except_body_scope,
                    guarded_call=guarded_call,
                    denial_kind=denial_kind,
                    location=location,
                    function=guarded_call.function,
                    provenance=Provenance(
                        source_layer="L2",
                        interpreter="exception_guard_detection",
                        confidence=0.8,
                        supporting_facts=(
                            f"try body call: {guarded_call.target_expression}",
                            f"handler denial: {denial_kind.value}",
                        ),
                    ),
                )
            )

    return tuple(guards)


def _first_line(cfg_view: ControlFlowView, block_id: int, default: int) -> int:
    locations = cfg_view.statement_locations(block_id)
    return locations[0].line if locations else default


def _find_swallowed_rejections(
    call_sites: tuple[CallSite, ...],
    cfg_view: ControlFlowView,
    *,
    effects: tuple[Effect, ...] = (),
) -> tuple[SwallowedRejection, ...]:
    """Identify ``try``/``except`` blocks whose try-body rejection ``raise`` is swallowed.

    A *swallowed rejection* (FLAW-319): the try body ``raise``s to reject input, but the
    matching handler neither re-raises nor denies (``except: pass`` / log-and-continue), so
    a validator that *looks* like it rejects never does. The ``raise`` keyword is invisible
    at the call-site level (``raise X(...)`` and ``X(...)`` look identical), so it is read
    from the CFG's ``"raise"`` edges:

    - a raise whose source LINE is lexically inside the try body is the *rejection*
      (``try_body_block_ids`` omits nested branch blocks, so line, not block membership);
    - a raise whose source BLOCK is a handler entry block is a *re-raise* (a denial).
    """
    from flawed.conditions import SwallowedRejection
    from flawed.core import Location, Provenance

    regions = cfg_view.try_regions
    if not regions or not call_sites:
        return ()
    raise_edges = cfg_view.raise_edges()
    if not raise_edges:
        return ()
    raise_block_ids = {block_id for block_id, _ in raise_edges}

    found: list[SwallowedRejection] = []

    for region in regions:
        if not region.handlers:
            continue
        try_block_ids = set(region.try_body_block_ids)
        handler_block_ids = {handler.entry_block_id for handler in region.handlers}
        facts = _exception_region_facts(
            call_sites,
            effects,
            cfg_view,
            try_block_ids=try_block_ids,
            handler_block_ids=handler_block_ids,
        )
        if not facts.try_calls:
            continue

        try_line = region.location.line
        handler_first_lines = {
            handler.entry_block_id: _first_line(cfg_view, handler.entry_block_id, try_line)
            for handler in region.handlers
        }
        first_except_line = min(handler_first_lines.values())

        rejections = [
            location
            for _, location in raise_edges
            if try_line <= location.line < first_except_line
        ]
        if not rejections:
            continue
        rejection = min(rejections, key=lambda location: location.line)

        for handler in region.handlers:
            # A re-raise sits in the handler's (straight-line) entry block and carries a
            # ``"raise"`` edge -- that denies, it does not swallow.
            if handler.entry_block_id in raise_block_ids:
                continue
            handler_calls = facts.handler_calls_by_block.get(handler.entry_block_id, ())
            handler_effects = facts.handler_effects_by_block.get(handler.entry_block_id, ())
            if _classify_handler_denial(handler_calls, handler_effects) is not None:
                continue

            guarded_call = facts.try_calls[-1]
            location = Location(
                file=region.location.file,
                line=region.location.line,
                column=region.location.column,
                end_line=region.location.end_line,
                end_column=region.location.end_column,
            )
            found.append(
                SwallowedRejection(
                    try_body=ConcreteCodeScope(
                        call_sites=facts.try_calls,
                        effects=facts.try_effects,
                        cfg=cfg_view.restricted_to(frozenset(try_block_ids)),
                    ),
                    except_body=ConcreteCodeScope(
                        call_sites=handler_calls,
                        effects=handler_effects,
                        cfg=cfg_view.restricted_to(frozenset({handler.entry_block_id})),
                    ),
                    guarded_call=guarded_call,
                    raise_location=rejection,
                    location=location,
                    function=guarded_call.function,
                    provenance=Provenance(
                        source_layer="L2",
                        interpreter="swallowed_rejection_detection",
                        confidence=0.8,
                        supporting_facts=(
                            f"rejection raise at line {rejection.line}",
                            "handler neither re-raises nor denies",
                        ),
                    ),
                )
            )

    return tuple(found)


def _exception_region_facts(
    call_sites: tuple[CallSite, ...],
    effects: tuple[Effect, ...],
    cfg_view: ControlFlowView,
    *,
    try_block_ids: set[int],
    handler_block_ids: set[int],
) -> _ExceptionRegionFacts:
    """Partition calls/effects into try-body and except-handler CFG blocks."""
    try_calls: list[CallSite] = []
    handler_calls_by_block: dict[int, list[CallSite]] = {}
    try_effects: list[Effect] = []
    handler_effects_by_block: dict[int, list[Effect]] = {}

    for call in call_sites:
        block_id = cfg_view.block_id_for(call.location)
        if block_id in try_block_ids:
            try_calls.append(call)
        elif block_id in handler_block_ids:
            handler_calls_by_block.setdefault(block_id, []).append(call)

    for effect in effects:
        block_id = cfg_view.block_id_for(effect.location)
        if block_id in try_block_ids:
            try_effects.append(effect)
        elif block_id in handler_block_ids:
            handler_effects_by_block.setdefault(block_id, []).append(effect)

    return _ExceptionRegionFacts(
        try_calls=tuple(try_calls),
        try_effects=tuple(try_effects),
        handler_calls_by_block={
            block_id: tuple(calls) for block_id, calls in handler_calls_by_block.items()
        },
        handler_effects_by_block={
            block_id: tuple(block_effects)
            for block_id, block_effects in handler_effects_by_block.items()
        },
    )


def _classify_handler_denial(
    handler_calls: tuple[CallSite, ...],
    handler_effects: tuple[Effect, ...],
) -> DenialKind | None:
    """Classify the denial kind of an except handler from its call sites.

    Returns ``None`` if no denial pattern is recognized.
    """
    from flawed.conditions import DenialKind

    if any(effect.category is EffectCategory.RESPONSE_WRITE for effect in handler_effects):
        return DenialKind.RETURN_ERROR

    for call in handler_calls:
        denial_kind = _call_denial_kind(call.target_expression)
        if denial_kind is not None:
            return denial_kind

    # Also check for raise patterns — the handler might have a raise
    # without a call site (e.g., bare `raise` or `raise HttpError(...)`)
    # Those appear as call sites to the constructor
    for call in handler_calls:
        expr = call.target_expression
        for kw in _RAISE_KEYWORDS:
            if kw in expr:
                return DenialKind.RAISE
    return None


def _call_denial_kind(target_expression: str) -> DenialKind | None:
    """Classify denial semantics from a handler call target."""
    from flawed.conditions import DenialKind

    expr = target_expression.lower()
    denial_kind: DenialKind | None = None
    if any(ind in expr for ind in _ABORT_INDICATORS):
        denial_kind = DenialKind.ABORT
    elif any(ind in expr for ind in _REDIRECT_INDICATORS):
        denial_kind = DenialKind.REDIRECT
    elif "raise" in expr or "exception" in expr:
        denial_kind = DenialKind.RAISE
    elif "return" in expr:
        denial_kind = DenialKind.RETURN_ERROR
    return denial_kind
