"""Same-logical-entity correlation primitive (FLAW-126).

An interpretation inconsistency is, by definition, a claim about *one* logical input:
two derivations interpret the SAME request value incompatibly. Yet the flat
``reads()`` / ``calls()`` / ``predicates()`` queries expose no same-origin join,
so every rule that needs one has hand-rolled it -- and most got it wrong:

* An earlier credential-divergence rule intersected credential *keys* by hand
  (correct, but ~40 unreadable lines).
* A transform-divergence rule counted any two differently-named transform calls
  anywhere in a route, with no shared-input check at all -- pairing
  ``logger.debug`` with ``.lower`` on real code.
* A name-collision rule correlated by the bare key *name* string, so a reused name (``token``
  as an API ``?token=`` query guard vs. an unrelated ``<token>`` URL path
  parameter) collapsed two different entities into one false positive.

This module provides that join once, correctly. The unit of correlation is a
:class:`LogicalInput` -- a request input's identity under a chosen
:class:`InputEquivalence`. Two derivations correlate when they share a
``LogicalInput``.

The equivalence is explicit because "same logical input" genuinely means
different things to different rules:

* :attr:`InputEquivalence.EXACT` -- same source type *and* key. "Literally the
  same value." Used when a rule asserts two derivations consume one identical
  value (e.g. the same string normalized two ways).
* :attr:`InputEquivalence.SUBSTITUTABLE_CONTAINER` -- same key, and both sources
  are *caller-substitutable* request lanes. A URL path segment
  (:class:`~flawed.inputs.PathParam`) is bound by the route pattern and cannot
  be forged into a query/body field, so it is its own family; every other
  container is mutually substitutable. Used when a rule asserts that validation
  and use disagree about *where* to read one submittable field.
* :attr:`InputEquivalence.SAME_CREDENTIAL` -- same key across the credential
  containers (header / cookie / query). A bearer token presented in any of these
  is the same credential. Used by credential-divergence rules.

The primitive stays in Layer 3 and composes the existing
:meth:`~flawed.flow.ValueHandle.derived_from` query and ``reads()`` facts; it
adds no Semantic-Layer surface.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

from flawed.core import Key
from flawed.inputs import AnyContainer, Cookie, Header, PathParam, Query

if TYPE_CHECKING:
    from collections.abc import Iterable

    from flawed.flow import ValueHandle
    from flawed.inputs import InputRead, InputSource


class InputEquivalence(Enum):
    """How strictly two request inputs must match to be the *same* logical input.

    See the module docstring for when each applies.
    """

    EXACT = "exact"
    SUBSTITUTABLE_CONTAINER = "substitutable_container"
    SAME_CREDENTIAL = "same_credential"


@dataclass(frozen=True)
class LogicalInput:
    """The identity of a request input under an :class:`InputEquivalence`.

    Two derivations operate on the same logical entity exactly when they yield
    equal ``LogicalInput`` values. ``family`` groups source types that the
    equivalence treats as interchangeable; ``key`` is the parameter name.
    """

    family: str
    """Equivalence-class label for the source container(s)."""

    key: str
    """The request parameter key/name."""

    def __repr__(self) -> str:
        return f"LogicalInput({self.family}:{self.key})"


#: Credential-bearing containers: a token in any of these is the same credential.
_CREDENTIAL_TYPES: frozenset[type] = frozenset({Header, Cookie, Query})


def source_key(source: InputSource) -> str | None:
    """The correlation key of an input source, or ``None`` for a wildcard.

    Delegates to the typed :attr:`~flawed.inputs.InputSource.leaf_identifier`
    (FLAW-271): one home for key extraction across the differently-named
    identifying fields (``key`` / ``name`` / ``field`` / ``path`` /
    ``parameter``), with a JSONPath reduced to its trailing segment
    (``$.user.id`` -> ``id``) so a JSON field correlates with the same-named
    form/query field.  The previous hand-rolled loop omitted ``parameter``, so
    ``DependencyInput`` sources never correlated by their parameter name — the
    false negative this closes (FLAW-270).
    """
    return source.leaf_identifier


def container_family(source_type: type) -> str:
    """The substitutable-container family for a source *type* (FLAW-126).

    A :class:`~flawed.inputs.PathParam` is bound by the URL route pattern and is
    never an caller-forgeable alias of a query/body/header field, so it forms
    its own family; all other containers are mutually substitutable. This is the
    distinction that separates a real container-split (``amount`` in JSON vs.
    form) from a mere name collision (``token`` in the query string vs. the URL
    path).
    """
    return "PATH" if source_type is PathParam else "FORGEABLE"


def logical_input(source: InputSource, equivalence: InputEquivalence) -> LogicalInput | None:
    """The :class:`LogicalInput` identity of *source*, or ``None`` if it has none.

    Returns ``None`` for wildcard sources (no key) and, under
    :attr:`InputEquivalence.SAME_CREDENTIAL`, for non-credential containers --
    so callers can map a read set to identities and simply drop the misses.
    """
    key = source_key(source)
    if key is None:
        return None
    if equivalence is InputEquivalence.SAME_CREDENTIAL:
        if type(source) not in _CREDENTIAL_TYPES:
            return None
        return LogicalInput("CREDENTIAL", key)
    if equivalence is InputEquivalence.SUBSTITUTABLE_CONTAINER:
        return LogicalInput(container_family(type(source)), key)
    return LogicalInput(type(source).__name__, key)


def same_logical_input(a: InputSource, b: InputSource, equivalence: InputEquivalence) -> bool:
    """Whether two input sources denote the same logical input under *equivalence*."""
    a_input = logical_input(a, equivalence)
    return a_input is not None and a_input == logical_input(b, equivalence)


def read_inputs(
    reads: Iterable[InputRead], equivalence: InputEquivalence
) -> frozenset[LogicalInput]:
    """The set of logical inputs observed by a collection of reads."""
    return frozenset(
        identity
        for read in reads
        if (identity := logical_input(read.source, equivalence)) is not None
    )


def _derivation_probe(source: InputSource, equivalence: InputEquivalence) -> InputSource:
    """The source to probe ``derived_from`` with for *source* under *equivalence*.

    Under :attr:`InputEquivalence.SAME_CREDENTIAL` we probe container-blind (a
    credential traced through an ``extract_token`` helper may lose its concrete
    container type), matching the established credential-divergence semantics.
    Otherwise we probe the concrete source so the type is part of the identity.
    """
    if equivalence is InputEquivalence.SAME_CREDENTIAL:
        return AnyContainer(key=Key(source_key(source) or ""))
    return source


def value_inputs(
    value: ValueHandle,
    among: Iterable[InputRead],
    equivalence: InputEquivalence,
) -> frozenset[LogicalInput]:
    """The logical inputs that flow into *value*, drawn from candidate *among* reads.

    For each candidate read whose source has an identity under *equivalence*, we
    ask whether *value* is :meth:`~flawed.flow.ValueHandle.derived_from` that
    source (interprocedurally), and keep the identities that match. This is the
    value-level counterpart to :func:`read_inputs`.
    """
    found: set[LogicalInput] = set()
    for read in among:
        source = read.source
        identity = logical_input(source, equivalence)
        if identity is None or identity in found:
            continue
        if value.derived_from(_derivation_probe(source, equivalence)):
            found.add(identity)
    return frozenset(found)
