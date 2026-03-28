"""Layer 1 data types — frozen structural facts produced by the extraction pipeline.

Every type here is a frozen dataclass or an enum.  All collection fields
use ``tuple`` for deep immutability.  All optional fields use ``X | None``.

These types are internal to the ``_index`` package.  Layer 2 converts
them into public Rule API (Layer 3) domain objects.

Naming convention — L1 types use qualified names to avoid collision with
the consumer-facing Layer 3 types:

    SourceSpan         (L1)  →  Location          (L3)
    ExtractionProvenance (L1)  →  Provenance        (L3)
    FunctionRecord     (L1)  →  Function          (L3)
    ClassRecord        (L1)  →  Class             (L3)
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Literal

# =====================================================================
# Enums
# =====================================================================


class AccessKind(Enum):
    """Kind of attribute or container access.

    The runtime emits ``ATTR`` for plain attribute reads and writes,
    ``SUBSCRIPT`` for container key reads and writes, ``AUGMENTED`` for
    augmented assignment on attributes and subscripts, and ``DEL`` for
    delete operations. ``CALL_MUTATOR`` covers common mutating method calls.
    """

    ATTR = "attr"
    """Plain attribute access: ``obj.name``."""

    SUBSCRIPT = "subscript"
    """Subscript access: ``obj[key]``."""

    DEL = "del"
    """Deletion: ``del obj.name`` or ``del obj[key]``."""

    AUGMENTED = "augmented"
    """Augmented assignment on attribute: ``obj.name += val``."""

    CALL_MUTATOR = "call_mutator"
    """Mutating method call: ``list.append(val)``, ``set.add(val)``."""


class AliasMechanism(Enum):
    """How a name alias was created."""

    IMPORT_ALIAS = "import_alias"
    """``import x as y`` or ``from m import x as y``."""

    ASSIGNMENT_ALIAS = "assignment_alias"
    """``y = x`` (direct name rebinding)."""

    WILDCARD_IMPORT = "wildcard_import"
    """``from m import *``."""


class AssignmentKind(Enum):
    """Kind of assignment statement."""

    SIMPLE = "simple"
    """``x = val``."""

    AUGMENTED = "augmented"
    """``x += val``."""

    UNPACKING = "unpacking"
    """``a, b = val``."""

    ANNOTATED = "annotated"
    """``x: int = val``."""


class EdgeSource(Enum):
    """Origin of a call-graph edge."""

    AST = "ast"
    """Call edge extracted by LibCST traversal with FQN resolution."""

    HIERARCHY = "hierarchy"
    """Edge resolved through class hierarchy (future until MRO facts are produced)."""


class ErrorKind(Enum):
    """Classification of an extraction pipeline error."""

    PARSE = "parse"
    """Source file could not be parsed."""

    ASTROID = "astroid"
    """astroid inference failed on a node or module."""

    BASEDPYRIGHT = "basedpyright"
    """basedpyright type enrichment failed."""

    MYPY = "mypy"
    """mypy batch type enrichment failed."""

    CFG = "cfg"
    """CFG construction failed (unsupported construct or internal error)."""

    RESOLUTION = "resolution"
    """FQN or import resolution failed."""

    VALUE_FLOW = "value_flow"
    """Value-flow edge computation failed."""


class FlowKind(Enum):
    """Kind of intra-function value-flow edge.

    The current runtime emits assignment, alias, unpack, augmented assignment,
    parameter-default assignment, call argument, return-expression, chained
    assignment, comprehension-binding, attribute-write, and yield edges.
    """

    ASSIGN = "assign"
    """Simple assignment: ``x = expr``."""

    ARGUMENT = "argument"
    """Argument passing at a call site."""

    RETURN = "return"
    """Return value at a return statement."""

    ALIAS = "alias"
    """Name aliasing: ``y = x`` where x is a known entity."""

    UNPACK = "unpack"
    """Unpacking assignment: ``a, b = expr``."""

    AUGMENTED_ASSIGN = "augmented_assign"
    """Augmented assignment: ``x += expr``."""

    ANNOTATED_ASSIGN = "annotated_assign"
    """Annotated assignment: ``x: int = expr``."""

    CHAIN = "chain"
    """Chained assignment inter-target link: ``x = y = val`` → y flows to x."""

    COMPREHENSION_BINDING = "comprehension_binding"
    """Comprehension variable binding: ``[... for x in expr]``."""

    ATTRIBUTE_WRITE = "attribute_write"
    """Attribute or subscript write: ``obj.attr = expr``."""

    YIELD = "yield"
    """Yield expression: ``yield expr`` or ``yield from expr``."""

    TRANSFORM_INPUT = "transform_input"
    """Operand feeding a call-transform: ``y = x.lower()`` → ``x`` flows to ``y``.

    Emitted for the receiver and non-literal arguments of a call expression on
    the right-hand side of an assignment, so provenance queries
    (``derived_from`` / ``flows_to`` / ``shares_origin``) follow a value through
    an intra-function transform.  Deliberately **not** whole-value-preserving:
    the value is *derived* from the operand but is not the operand unchanged, so
    this kind is excluded from the whole-value-preservation step kinds and from
    the assignment/alias-family kind sets used elsewhere.
    """


class FunctionKind(Enum):
    """Structural kind of a Python callable."""

    TOP_LEVEL = "top_level"
    """Module-level function."""

    METHOD = "method"
    """Instance, class, or static method defined inside a class body."""

    NESTED = "nested"
    """Function defined inside another function."""

    LAMBDA = "lambda"
    """Lambda expression."""


class ParameterKind(Enum):
    """Kind of function parameter."""

    POSITIONAL_ONLY = "positional_only"
    """Before ``/`` in the parameter list."""

    POSITIONAL_OR_KEYWORD = "positional_or_keyword"
    """Standard parameter (no ``/`` or ``*`` boundary)."""

    KEYWORD_ONLY = "keyword_only"
    """After ``*`` or ``*args`` in the parameter list."""

    VAR_POSITIONAL = "var_positional"
    """``*args``."""

    VAR_KEYWORD = "var_keyword"
    """``**kwargs``."""


class ResolutionStatus(Enum):
    """Status of FQN or call-target resolution."""

    RESOLVED = "resolved"
    """Successfully resolved to a single FQN."""

    UNRESOLVED = "unresolved"
    """Could not be resolved by any tool."""

    PARTIAL = "partial"
    """Partially resolved (e.g. module known but name ambiguous)."""


# =====================================================================
# Foundation types
# =====================================================================


@dataclass(frozen=True, slots=True)
class SourceSpan:
    """Layer 1 source position — a complete file span.

    All fields are required (unlike Layer 3 ``Location`` which allows
    optional end positions).  Coordinates are 1-based line, 0-based
    column, consistent with LSP.
    """

    file: str
    """Relative path to the source file within the repository."""

    line: int
    """1-based start line number."""

    column: int
    """0-based start column offset."""

    end_line: int
    """1-based end line number."""

    end_column: int
    """0-based end column offset."""


@dataclass(frozen=True, slots=True)
class ExtractionProvenance:
    """Tracks which extraction pass produced a structural fact.

    Every record, edge, and fact in Layer 1 carries provenance so that
    downstream consumers can trace any piece of data back to the tool
    and pipeline step that produced it.
    """

    producer: str
    """Name of the extraction pass (e.g. ``"structural_entity_pass"``)."""

    producer_version: str
    """Version of the producer pass."""

    artifact: str
    """Source artifact path within the analysis store."""


@dataclass(frozen=True)
class ResolutionProvenance:
    """Provenance for a multi-tool conflict resolution decision.

    When multiple tools (LibCST, astroid, basedpyright) produce
    conflicting data for the same code construct, this record documents
    which tool's output was selected and why.
    """

    selected_source: str
    """Tool whose output was chosen (``"consensus"``, ``"astroid"``, etc.)."""

    contributing_sources: tuple[str, ...]
    """All tools that provided data for this fact."""

    alternatives: tuple[str, ...] | None
    """Rejected alternative values, preserved for audit."""

    verification_method: str | None
    """Method used to break the tie (``"import_chain"``, ``"filesystem"``, etc.)."""

    confidence: float
    """Confidence score in ``[0.0, 1.0]``.  Consensus = 1.0."""


# =====================================================================
# Record types — alphabetical
# =====================================================================


@dataclass(frozen=True)
class AliasFact:
    """A name alias created by import or assignment."""

    original_fqn: str
    """FQN of the original name."""

    alias_name: str
    """The alias name introduced."""

    mechanism: AliasMechanism
    """How the alias was created."""

    location: SourceSpan
    """Source location of the aliasing statement."""

    is_conditional: bool = False
    """``True`` when the import is inside ``if TYPE_CHECKING`` or ``try/except ImportError``."""


@dataclass(frozen=True)
class AssignmentFact:
    """An assignment target and its value.

    Used in value-flow construction to track how values propagate
    through assignments within a function.
    """

    target: str
    """Target name or expression (source text)."""

    target_location: SourceSpan
    """Source location of the assignment target."""

    value_expression: str
    """Source text of the assigned value."""

    value_location: SourceSpan
    """Source location of the value expression."""

    kind: AssignmentKind
    """What kind of assignment this is."""

    containing_function_fqn: str | None
    """FQN of the containing function, or ``None`` for module-level."""


@dataclass(frozen=True)
class AttributeAccess:
    """A read or write access on an object attribute or container key.

    Captures plain attribute reads/writes (``obj.attr``), subscript
    reads/writes (``obj[key]``), augmented writes (``obj.attr += val``,
    ``obj[key] += val``), deletes (``del obj.attr``, ``del obj[key]``), and
    common mutating method calls (``list.append(val)``, ``dict.update(...)``).
    """

    target_expr: str
    """Source text of the object expression (e.g. ``"request"`` in ``request.args``)."""

    attr_name: str
    """Attribute or key name."""

    is_write: bool
    """``True`` for writes (assignment, augmented, del, call_mutator)."""

    access_kind: AccessKind
    """Classification of the access pattern."""

    value_expr: str | None
    """Source text of the written value (writes only, ``None`` for reads)."""

    containing_function_fqn: str | None
    """FQN of the containing function, or ``None`` for module-level."""

    location: SourceSpan
    """Source location of the access."""

    provenance: ExtractionProvenance
    """Which extraction pass produced this fact."""


@dataclass(frozen=True)
class BranchCondition:
    """A branch point in the control-flow graph with direction taken."""

    condition_expr: str
    """Source text of the branch condition."""

    direction: bool
    """Which branch was taken (``True`` or ``False``)."""

    location: SourceSpan
    """Source location of the branch condition."""


@dataclass(frozen=True)
class ValuePredicate:
    """A predicate expression produced as a VALUE, not a branch test.

    Captured when a comparison / membership / identity / truthiness
    expression appears in *value* position — a ``return`` value
    (``return token is not None``), an assignment RHS
    (``is_admin = role == "admin"``), or a ternary operand. Unlike a
    branch :class:`BranchCondition`, a value predicate carries **no**
    control-flow edges: it is recorded purely as source text plus a span,
    so that Layer 2's ``predicates()`` fact can lift it without disturbing
    the branch-only ``conditions()`` contract.

    The L1 layer records the expression and its position; structural
    classification (MEMBERSHIP / COMPARISON / IDENTITY / TRUTHINESS) is
    deferred to Layer 2, which already owns that vocabulary.
    """

    expression: str
    """Source text of the predicate expression (e.g. ``token is not None``)."""

    location: SourceSpan
    """Source location of the predicate expression."""

    position: Literal["return", "assign", "ternary"]
    """Where the predicate was produced as a value."""


@dataclass(frozen=True)
class CFGBlock:
    """A basic block in the control-flow graph.

    A maximal straight-line sequence of statements with no branches or
    branch targets in the middle.
    """

    id: int
    """Unique block identifier within the function's CFG."""

    statements: tuple[SourceSpan, ...]
    """Source locations of each statement in this block."""

    successors: tuple[int, ...]
    """Block IDs of successor blocks."""

    predecessors: tuple[int, ...]
    """Block IDs of predecessor blocks."""

    condition_expr: str | None
    """Branch condition source text if this block ends with a branch."""

    condition_location: SourceSpan | None = None
    """Source location of ``condition_expr`` when this block ends with a branch."""

    value_predicates: tuple[ValuePredicate, ...] = ()
    """Predicate expressions produced as values in this block (no branch edges)."""


@dataclass(frozen=True)
class CFGEdge:
    """An edge in the control-flow graph between two basic blocks."""

    source_id: int
    """Block ID of the source block."""

    target_id: int
    """Block ID of the target block."""

    label: str
    """Edge label (e.g. ``"true"``, ``"false"``, ``"exception"``, ``"fallthrough"``)."""

    is_exceptional: bool
    """``True`` if this edge represents an exception control-flow path."""


@dataclass(frozen=True)
class CFGPath:
    """A concrete execution path through the control-flow graph."""

    blocks: tuple[CFGBlock, ...]
    """Ordered sequence of blocks traversed."""

    conditions: tuple[BranchCondition, ...] = ()
    """Ordered branch conditions traversed by the path."""


@dataclass(frozen=True)
class ExceptHandler:
    """Metadata for a single except clause within a try/except region."""

    exception_types: tuple[str, ...]
    """Qualified names of caught exception types (empty for bare ``except:``)."""

    entry_block_id: int
    """Block ID of the handler's first basic block."""

    name: str | None = None
    """Bound exception variable name (``as e``), or ``None``."""


@dataclass(frozen=True)
class TryExceptRegion:
    """Structured metadata for a try/except/finally region in the CFG.

    Captures the block topology of a try statement so that higher layers
    can identify which blocks form the try body vs. each handler without
    re-parsing the AST.
    """

    try_body_block_ids: tuple[int, ...]
    """Block IDs that form the try body (in execution order)."""

    handlers: tuple[ExceptHandler, ...]
    """Metadata for each except clause, in source order."""

    finally_block_id: int | None
    """Entry block ID of the finally clause, or ``None``."""

    else_block_id: int | None
    """Entry block ID of the else clause, or ``None``."""

    location: SourceSpan
    """Source location of the ``try`` keyword."""


@dataclass(frozen=True)
class CallArgument:
    """A single argument at a call site."""

    position: int | None
    """0-based position, or ``None`` for keyword-only arguments."""

    keyword: str | None
    """Keyword name, or ``None`` for positional-only arguments."""

    expression: str
    """Source text of the argument value."""

    location: SourceSpan
    """Source location of the argument expression."""


@dataclass(frozen=True)
class CallEdge:
    """A call-graph edge between two functions.

    Carries full metadata: arguments, resolution status, edge source,
    and provenance.  Edges are produced by AST traversal and hierarchy
    resolution and merged per §5 of the spec.
    """

    caller_fqn: str
    """FQN of the calling function."""

    callee_fqn: str | None
    """FQN of the called function, or ``None`` when fully unresolved."""

    arguments: tuple[CallArgument, ...]
    """Arguments at the call site."""

    resolution: ResolutionStatus
    """Whether the callee FQN was successfully resolved."""

    source: EdgeSource
    """Which tool produced this edge."""

    unresolved_reason: str | None
    """Explanation when resolution is not RESOLVED."""

    location: SourceSpan
    """Source location of the call expression."""

    provenance: ExtractionProvenance
    """Which extraction pass produced this edge."""

    call_expression: str | None = None
    """Source text of the call *target* (``db.execute`` in ``db.execute(q)``), or ``None``.

    The AST extractor mints the callable target spelling; the argument source text
    lives in :attr:`arguments`. A two-stage decorator call whose callee is itself a
    call (``limiter.limit("5/m")(auth)``) keeps its full expression.
    ``target_expression`` in the public ``CallSite`` API derives directly from this
    field, so the two must speak the same (target-only) representation.
    """

    dynamic_dispatch_kind: str | None = None
    """Dynamic dispatch shape for unresolved AST call edges, or ``None``."""

    receiver_expression: str | None = None
    """Source text of a method-call receiver (``x`` in ``x.lower()``), or ``None``.

    Populated for AST-sourced method calls whose ``func`` is an attribute
    access.  ``None`` for plain function calls (``foo()``) and for edges from
    extractors that do not carry the call AST.  Drives ``CallSite.receiver``
    (FLAW-187), the method-call subject provenance handle.
    """

    receiver_location: SourceSpan | None = None
    """Source location of the receiver expression, or ``None`` (see above)."""


@dataclass(frozen=True)
class ClassRecord:
    """Layer 1 raw structural record for a Python class.

    The current runtime records class-local facts from LibCST and enriches
    project-local hierarchy facts after import resolution: deterministic local
    C3 MRO chains, subclass closure, and inherited project-local methods.
    External or unresolved bases are preserved in ``bases`` but do not create
    fake MRO entries. Metaclass inference remains future work.
    """

    fqn: str
    """Fully qualified name."""

    name: str
    """Short class name."""

    file: str
    """Relative file path."""

    bases: tuple[str, ...]
    """Base class FQNs (or raw names when unresolved)."""

    mro_chain: tuple[str, ...]
    """FQNs in locally resolved method resolution order.

    Complete for classes whose direct bases are project-local or ``object``.
    Classes with external or unresolved direct bases contain only their own FQN.

    Named ``mro_chain`` instead of ``mro`` to avoid shadowing
    ``type.mro`` which Python's dataclass machinery picks up as a
    default value from the metaclass.
    """

    mro_complete: bool
    """Whether MRO was fully resolved from project-local sources.

    ``True`` when all bases are project-local or ``object``.
    ``False`` when any base is external, unresolved, or cyclic.
    """

    method_names: tuple[str, ...]
    """Short names of methods defined directly on this class."""

    class_var_names: tuple[str, ...]
    """Short names of class-level variable assignments."""

    is_abstract: bool
    """Whether the class is abstract.

    ``True`` when the class inherits from ``abc.ABC``, uses
    ``metaclass=abc.ABCMeta``, or contains methods decorated with
    ``@abstractmethod``.
    """

    metaclass: str | None
    """FQN of the metaclass, or ``None`` when not declared or not detected."""

    subclasses: tuple[str, ...]
    """Project-local FQNs of direct subclasses."""

    all_subclasses: tuple[str, ...]
    """Project-local FQNs of transitive descendants."""

    inherited_methods: tuple[InheritedMethod, ...]
    """Project-local methods inherited through the resolved MRO prefix."""

    hierarchy_gaps: tuple[HierarchyGap, ...]
    """Unresolved base classes that prevented complete MRO computation."""

    location: SourceSpan
    """Source location of the ``class`` statement."""

    provenance: ExtractionProvenance
    """Which extraction pass produced this record."""


@dataclass(frozen=True)
class ComprehensionBindingFact:
    """A target binding introduced by a Python comprehension ``for`` clause."""

    target: str
    """Target expression bound by the comprehension clause."""

    target_location: SourceSpan
    """Source location of the bound target."""

    iterable_expression: str
    """Source text of the iterable expression that feeds the binding."""

    iterable_location: SourceSpan
    """Source location of the iterable expression."""

    comprehension_expr: str
    """Source text of the full comprehension expression."""

    comprehension_location: SourceSpan
    """Source location of the full comprehension expression."""

    containing_function_fqn: str | None
    """FQN of the containing function, or ``None`` for module-level."""

    provenance: ExtractionProvenance
    """Which extraction pass produced this fact."""


@dataclass(frozen=True)
class DecoratorFact:
    """A decorator application on a function or class.

    Records both the syntactic name and the resolved FQN (when
    determinable), plus argument expressions.
    """

    name: str
    """Syntactic short name as written in source."""

    fqn: str | None
    """Resolved FQN, or ``None`` when unresolvable."""

    args: tuple[str, ...]
    """Positional argument source expressions."""

    kwargs: tuple[tuple[str, str], ...]
    """Keyword argument ``(name, value_source_text)`` pairs."""

    target_fqn: str
    """FQN of the decorated function or class."""

    application_order: int
    """0 = innermost (closest to the ``def``/``class`` keyword)."""

    location: SourceSpan
    """Source location of the decorator line."""

    provenance: ExtractionProvenance
    """Which extraction pass produced this fact."""


@dataclass(frozen=True)
class ExtractionError:
    """An error encountered during the extraction pipeline.

    Non-fatal errors are recorded and attached to affected entities
    so that downstream layers can degrade gracefully.  Fatal errors
    abort the extraction for the affected file.
    """

    file: str
    """File where the error occurred."""

    pass_name: str
    """Extraction step that encountered the error."""

    error_kind: ErrorKind
    """Classification of the error."""

    message: str
    """Human-readable error description."""

    is_fatal: bool
    """Whether this error prevented further extraction for the file.

    Per-*file* semantics: the affected file is gapped (absent from the index),
    but other files and the repo as a whole are unaffected.  Do NOT use this as
    a repo-level abort signal — see :attr:`aborts_pipeline`.
    """

    location: SourceSpan | None
    """Specific source location, or ``None`` for file-level errors."""

    aborts_pipeline: bool = False
    """Repo-level failure: extraction cannot proceed at all (vs. a per-file gap).

    Distinct from :attr:`is_fatal`, which is per-file.  Only genuinely
    repo-wide conditions set this.  A single unparsable file must be recorded as
    a gap and skipped — it must NOT abort analysis of the rest of the repo (FLAW-264).
    Defaulted so existing call sites and older caches round-trip as ``False``.
    """


@dataclass(frozen=True)
class FunctionRecord:
    """Layer 1 raw structural record for a Python callable.

    Captures everything knowable about a function from structural
    analysis alone: signature, decorators, nesting, location.
    """

    fqn: str
    """Fully qualified name."""

    name: str
    """Short function name."""

    file: str
    """Relative file path."""

    line: int
    """1-based line number of the ``def`` keyword (convenience alias)."""

    params: tuple[Parameter, ...]
    """Function parameters in declaration order."""

    decorator_names: tuple[str, ...]
    """Syntactic short names of decorators."""

    decorator_fqns: tuple[str | None, ...]
    """Resolved FQNs of decorators (parallel to ``decorator_names``)."""

    kind: FunctionKind
    """Structural classification (top-level, method, nested, lambda)."""

    is_method: bool
    """``True`` if this function is a method inside a class."""

    is_nested: bool
    """``True`` if this function is defined inside another function."""

    is_async: bool
    """``True`` if this is an ``async def`` function."""

    parent_class: str | None
    """FQN of the containing class, or ``None``."""

    location: SourceSpan
    """Full source span of the function definition."""

    provenance: ExtractionProvenance
    """Which extraction pass produced this record."""

    parent_function: str | None = None
    """FQN of the containing function, or ``None``."""


@dataclass(frozen=True)
class ImportFact:
    """An import statement with resolution metadata."""

    module: str
    """Imported module name."""

    names: tuple[str, ...]
    """Imported names (empty for bare ``import module``)."""

    aliases: tuple[tuple[str, str], ...]
    """``(original_name, alias_name)`` pairs from ``as`` clauses."""

    is_from_import: bool
    """``True`` for ``from module import ...``, ``False`` for ``import module``."""

    location: SourceSpan
    """Source location of the import statement."""

    provenance: ExtractionProvenance
    """Which extraction pass produced this fact."""

    is_conditional: bool = False
    """``True`` when the import is inside ``if TYPE_CHECKING`` or ``try/except ImportError``."""

    is_relative: bool = False
    """``True`` for relative imports (``from . import ...``).

    ``module`` carries the *resolved* absolute module name for these, so the
    relative origin cannot be recovered from ``module`` alone. PEP 420
    namespace-prefix classification must exclude relative imports (a package's
    own intra-package imports are not evidence that the top directory is an
    imported namespace), so the flag is recorded explicitly.
    """


@dataclass(frozen=True)
class HierarchyGap:
    """An unresolved base class in a class hierarchy.

    Produced when a base class cannot be resolved to a project-local class
    definition, preventing complete MRO computation.  The gap records the
    raw base expression and the reason for non-resolution.
    """

    base_expression: str
    """Raw base class expression (FQN or syntactic name)."""

    reason: Literal["external", "unresolved", "cycle"]
    """Why the base could not be resolved:

    - ``"external"``: base is a known import from a non-project module.
    - ``"unresolved"``: base could not be resolved to any known entity.
    - ``"cycle"``: base creates a cycle in the inheritance graph.
    """


@dataclass(frozen=True)
class InheritedMethod:
    """A future method inherited through the MRO."""

    name: str
    """Method name."""

    defining_class_fqn: str
    """FQN of the class that defines this method."""

    resolution: Literal["mro", "explicit"]
    """How the method was resolved: ``"mro"`` (automatic) or ``"explicit"`` (manual)."""


@dataclass(frozen=True)
class LocationFact:
    """Source location index entry for an entity.

    May be implicit in the index construction rather than a separate
    serialized type — included for completeness.
    """

    entity_fqn: str
    """FQN of the entity."""

    span: SourceSpan
    """Source location of the entity."""


@dataclass(frozen=True)
class Parameter:
    """A function parameter with its syntactic metadata."""

    name: str
    """Parameter name."""

    annotation: str | None
    """Source text of the type annotation, or ``None``."""

    default: str | None
    """Source text of the default value, or ``None``."""

    kind: ParameterKind
    """What kind of parameter this is (positional, keyword, etc.)."""

    position: int
    """0-based index in the parameter list."""

    location: SourceSpan
    """Source location of the parameter."""


@dataclass(frozen=True)
class ReturnFact:
    """A return statement and its optional returned expression."""

    expression: str | None
    """Source text of the returned expression, or ``None`` for bare ``return``."""

    expression_location: SourceSpan | None
    """Source location of the returned expression, or ``None`` for bare ``return``."""

    statement_location: SourceSpan
    """Source location of the ``return`` statement."""

    containing_function_fqn: str
    """FQN of the function containing the return statement."""

    provenance: ExtractionProvenance
    """Which extraction pass produced this fact."""


@dataclass(frozen=True)
class SymbolRef:
    """A reference to a symbol with resolution status."""

    name: str
    """Name as written in source."""

    fqn: str | None
    """Resolved FQN, or ``None`` when unresolvable."""

    resolution: ResolutionStatus
    """Resolution status."""

    location: SourceSpan
    """Source location of the reference."""

    provenance: ExtractionProvenance
    """Which extraction pass produced this fact."""


@dataclass(frozen=True)
class ValueFlowEdge:
    """An intra-function value-flow edge.

    Current edges track assignments, aliasing, unpacking, augmented assignment,
    parameter defaults, call arguments, return expressions, comprehension
    bindings, attribute writes, and yield expressions within a function or
    module.
    """

    source_expr: str
    """Source text of the source expression."""

    source_location: SourceSpan
    """Source location of the source expression."""

    target_expr: str
    """Source text of the target expression."""

    target_location: SourceSpan
    """Source location of the target expression."""

    kind: FlowKind
    """What kind of value flow this edge represents."""

    containing_function_fqn: str | None
    """FQN of the containing function, or ``None`` for module-level."""

    provenance: ExtractionProvenance
    """Which extraction pass produced this edge."""

    callsite_callee_fqn: str | None = None
    """Resolved call target for argument edges, or ``None`` when unresolved/not a call."""

    callsite_expr: str | None = None
    """Source text of the call-site callee expression for argument edges."""

    argument_position: int | None = None
    """0-based positional argument index for argument edges, or ``None``."""

    argument_keyword: str | None = None
    """Keyword name for keyword argument edges, or ``None``."""


@dataclass(frozen=True)
class YieldFact:
    """A yield or yield-from expression in a generator function.

    Captures the yielded expression and whether this is a ``yield from``
    delegation.  Generator semantics (suspension, resumption) are not
    modeled structurally — this is a data-flow observation only.
    """

    expression: str | None
    """Source text of the yielded expression, or ``None`` for bare ``yield``."""

    expression_location: SourceSpan | None
    """Source location of the yielded expression, or ``None`` for bare ``yield``."""

    statement_location: SourceSpan
    """Source location of the ``yield`` expression."""

    is_from: bool
    """``True`` for ``yield from expr``, ``False`` for plain ``yield expr``."""

    containing_function_fqn: str
    """FQN of the generator function containing this yield."""

    provenance: ExtractionProvenance
    """Which extraction pass produced this fact."""
