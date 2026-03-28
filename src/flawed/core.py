"""Foundational types shared across the Rule API domain model.

Every domain object carries a :class:`Location` for source-mapping and a
:class:`Provenance` record that documents which analysis produced the fact.

Type aliases :data:`Key` and :data:`JsonPath` give semantic meaning to
plain strings used as parameter names, header names, or JSONPath
expressions.

:class:`Provenance` is the public provenance type for Layer 2/3 domain
objects (routes, input reads, effects).  :class:`ExtractionProvenance`
is the internal provenance type for Layer 1 structural facts -- rule
authors should never encounter it directly.

Example::

    from flawed.core import Location, Provenance

    loc = Location(file="app.py", line=42, column=0)
    prov = Provenance(
        source_layer="L2",
        interpreter="flask_routes",
        confidence=0.95,
        supporting_facts=("decorator @app.route found",),
    )
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import NewType

Key = NewType("Key", str)
"""Typed key for request parameter names, header names, cookie names, etc.

Used wherever a domain object identifies a named value in an HTTP request
container (e.g. ``Query(key=Key("user_id"))``).  The ``NewType`` wrapper
lets mypy distinguish ``Key`` from arbitrary strings while remaining a
plain ``str`` at runtime.
"""

JsonPath = NewType("JsonPath", str)
"""JSONPath expression for addressing JSON body fields.

Follows the JSONPath draft syntax (``$.field``, ``$.nested.field``).
Used by :class:`~flawed.inputs.Json` to specify which part of a
JSON request body is being read.
"""


@dataclass(frozen=True)
class Location:
    """A specific position in source code.

    Coordinates use a **1-based line, 0-based column** system consistent
    with LSP and most editor integrations.  ``end_line`` / ``end_column``
    are ``None`` when only the start position is known (e.g. for a
    function-level location derived from the ``def`` keyword).

    Example::

        loc = Location(file="app.py", line=10, column=4, end_line=10, end_column=28)
    """

    file: str
    """Relative path to the source file within the analysis store."""

    line: int
    """1-based start line number."""

    column: int
    """0-based start column offset."""

    end_line: int | None = None
    """1-based end line number, or ``None`` if unknown."""

    end_column: int | None = None
    """0-based end column offset, or ``None`` if unknown."""

    def __repr__(self) -> str:
        return f"Location({self.file}:{self.line}:{self.column})"


@dataclass(frozen=True, slots=True)
class ExtractionProvenance:
    """Internal provenance for facts produced by Layer 1 (Code Index).

    Tracks which extraction pass produced a structural fact (e.g.
    function discovery, decorator extraction).  This type is internal
    to Layer 1 -- rule authors should never encounter it directly.
    Layer 2 converts L1 facts to domain objects carrying
    :class:`Provenance` instead.

    Example::

        prov = ExtractionProvenance(
            producer="structural_entity_pass",
            producer_version="1.0",
            artifact="normalized/functions.jsonl",
        )
    """

    producer: str
    """Name of the extraction pass that produced this fact."""

    producer_version: str
    """Version of the producer pass."""

    artifact: str
    """Source artifact path within the analysis store."""


@dataclass(frozen=True)
class Provenance:
    """Provenance for domain objects produced by Layer 2 and consumed by Layer 3.

    Every domain object that crosses the Layer 2 → Layer 3 boundary
    carries a ``Provenance`` recording which interpreter produced it,
    with what confidence, and which lower-level facts support the
    conclusion.

    This is the standard provenance type for the public Rule API.

    Example::

        prov = Provenance(
            source_layer="L2",
            interpreter="flask_routes",
            confidence=0.95,
            supporting_facts=("decorator @app.route found", "handler has request.json read"),
        )
    """

    source_layer: str
    """Layer identifier (``"L1"``, ``"L2"``)."""

    interpreter: str
    """Interpreter or pass name (``"flask_routes"``, ``"sqlalchemy_effects"``)."""

    confidence: float
    """Confidence score in ``[0.0, 1.0]``."""

    supporting_facts: tuple[str, ...] = ()
    """Lower-level facts that support this interpretation (empty for L1 facts)."""

    def __repr__(self) -> str:
        return f"Provenance({self.source_layer}/{self.interpreter}, conf={self.confidence:.2f})"


# ---------------------------------------------------------------------------
# Analysis gap tracking
# ---------------------------------------------------------------------------


class GapKind(Enum):
    """Classification of an analysis gap.

    Each value identifies a specific type of incomplete analysis that
    may affect downstream queries and detection results.  Gaps are
    propagated automatically through layers: Layer 1 extraction errors
    become gaps on Layer 2 domain objects, which are then carried into
    Layer 3 findings without rule-author intervention.

    Values:

    - ``PARSE_FAILURE`` -- source file could not be parsed
    - ``CFG_UNAVAILABLE`` -- CFG construction failed for a function
    - ``CFG_RECONSTRUCTION_FAILURE`` -- CFG-backed semantic reconstruction failed
    - ``SYMBOL_UNRESOLVED`` -- FQN resolution failed for a symbol
    - ``INFERENCE_FAILURE`` -- astroid, basedpyright, or mypy inference failed
    - ``CALL_GRAPH_INCOMPLETE`` -- call graph edges may be missing
    - ``INTERPRETER_ERROR`` -- a Layer 2 interpreter raised an exception
    - ``VALUE_FLOW_INCOMPLETE`` -- value-flow edges may be missing
    """

    PARSE_FAILURE = "parse_failure"
    CFG_UNAVAILABLE = "cfg_unavailable"
    CFG_RECONSTRUCTION_FAILURE = "cfg_reconstruction_failure"
    SYMBOL_UNRESOLVED = "symbol_unresolved"
    INFERENCE_FAILURE = "inference_failure"
    CALL_GRAPH_INCOMPLETE = "call_graph_incomplete"
    INTERPRETER_ERROR = "interpreter_error"
    VALUE_FLOW_INCOMPLETE = "value_flow_incomplete"


@dataclass(frozen=True)
class AnalysisGap:
    """An analysis limitation automatically propagated through layers.

    Produced by Layer 1 (from extraction errors) and Layer 2 (from
    interpreter failures).  Attached automatically to domain objects
    (:class:`~flawed.route.Route`, :class:`~flawed.function.Function`,
    :class:`~flawed.scopes.CodeScope`) and propagated into
    :class:`~flawed.evidence.Finding` objects without rule-author
    intervention.

    Rule authors never need to create or check for gaps explicitly.
    When a gap affects a finding, it is included in
    ``Finding.gaps`` automatically.

    Example::

        # Gaps propagate silently -- rule authors just use the API:
        for gap in route.gaps:
            print(gap.kind, gap.message)
    """

    kind: GapKind
    """What type of analysis limitation this represents."""

    message: str
    """Human-readable description of the gap."""

    affected_file: str | None = None
    """File affected by this gap, or ``None`` for global gaps."""

    affected_function: str | None = None
    """FQN of the affected function, or ``None`` for file-level gaps."""

    source_error: str | None = None
    """Original error message from Layer 1 or Layer 2, if available."""

    origin_phase: str | None = None
    """Pipeline phase that produced this gap (e.g. ``"route_conversion"``,
    ``"provider_engine"``).  Set at creation time by conversion modules;
    falls back to ``source_error`` prefix parsing when ``None``."""

    origin_provider: str | None = None
    """Provider that produced this gap, or ``None`` for non-provider gaps."""

    def __repr__(self) -> str:
        locus = self.affected_function or self.affected_file or "global"
        return f"AnalysisGap({self.kind.name}, {locus})"


# ---------------------------------------------------------------------------
# Repr helpers (shared across Layer 3 domain types)
# ---------------------------------------------------------------------------
#
# Domain objects embed heavy nested structures (a Route holds a Function, which
# holds Parameters; an Effect holds a Function and Provenance).  The dataclass
# auto-generated ``__repr__`` recurses through all of it, so echoing a single
# object in a REPL dumps ~1 KB and a collection dumps tens of KB.  Every L3
# domain type defines a concise one-line ``__repr__`` built from these helpers
# instead, leading with identity plus 2-3 facts and never recursing into nested
# domain objects.  The full structured dump remains available via ``vars(obj)``
# / ``dataclasses.asdict`` for callers who want it.


def _short_loc(location: Location | None) -> str:
    """Render a :class:`Location` as a compact ``file:line`` string.

    ``None`` (an unknown location) renders as ``"?"``.  Used by every
    domain ``__repr__`` so reprs stay one line and never recurse.
    """
    if location is None:
        return "?"
    return f"{location.file}:{location.line}"


def _short_expr(expression: str, limit: int = 48) -> str:
    """Collapse whitespace and truncate a source expression for one-line reprs.

    Multi-line expressions are flattened to a single space-separated line and
    truncated to *limit* characters with a trailing ellipsis, so a sprawling
    call expression never blows up a repr.
    """
    collapsed = " ".join(expression.split())
    if len(collapsed) <= limit:
        return collapsed
    return collapsed[: limit - 1] + "…"
