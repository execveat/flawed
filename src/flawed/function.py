"""Function, Parameter, and Decorator domain types.

These types represent Python callables discovered by Layer 1 (Code Index).
Every function in the analyzed repository -- top-level, method, nested,
lambda, or closure -- is represented as a :class:`Function` with its
parameters, location, and structural metadata.

Decorators at this layer are purely syntactic: they record *which*
decorators are applied and their arguments, but carry no security
interpretation.  Security meaning (e.g. ``@login_required`` implying an
auth check) is determined by Layer 2 interpreters.

Example::

    from flawed import open_repo

    kb = open_repo("path/to/store")
    fn = kb.functions.named("create_user").one()
    print(fn.fqn)  # "myapp.views.create_user"
    print(fn.kind)  # FunctionKind.TOP_LEVEL
    print(fn.params[0])  # Parameter(name="data", ...)
    print(fn.decorators)  # DecoratorCollection with @app.route, etc.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING

from flawed.core import _short_loc

if TYPE_CHECKING:
    from flawed.collections import (
        DecoratorCollection,
        FunctionCollection,
    )
    from flawed.core import AnalysisGap, Location, Provenance
    from flawed.scopes import CodeScope


class FunctionKind(Enum):
    """Classification of a Python callable.

    Determines the structural role of a function within its module.  The
    kind is assigned during Layer 1 discovery based on the AST position
    of the ``def`` / ``lambda`` node.

    Values:

    - ``TOP_LEVEL`` -- module-level ``def`` statement
    - ``METHOD`` -- ``def`` inside a ``class`` body
    - ``NESTED`` -- ``def`` inside another ``def`` (not a closure)
    - ``LAMBDA`` -- ``lambda`` expression
    - ``CLOSURE`` -- ``def`` inside another ``def`` that captures free variables
    """

    TOP_LEVEL = "top_level"
    METHOD = "method"
    NESTED = "nested"
    LAMBDA = "lambda"
    CLOSURE = "closure"


@dataclass(frozen=True)
class Parameter:
    """A single function parameter with type and default information.

    Extracted from the function signature by Layer 1.  The ``kind``
    field mirrors Python's :class:`inspect.Parameter` kind names.

    Example::

        param = fn.params[0]
        print(param.name)  # "user_id"
        print(param.annotation)  # "int" or None
        print(param.default)  # "0" or None
        print(param.kind)  # "positional_or_keyword"
    """

    name: str
    """Parameter name as written in the source."""

    annotation: str | None
    """Type annotation as source text, or ``None`` if unannotated."""

    default: str | None
    """Default value as source text, or ``None`` if no default."""

    kind: str
    """Parameter kind: ``positional_only``, ``positional_or_keyword``,
    ``keyword_only``, ``var_positional``, or ``var_keyword``."""

    def __repr__(self) -> str:
        sig = self.name
        if self.annotation is not None:
            sig += f": {self.annotation}"
        if self.default is not None:
            sig += f" = {self.default}"
        return f"Parameter({sig})"


@dataclass(frozen=True)
class Decorator:
    """A decorator applied to a function (syntactic only).

    Represents the ``@name(args)`` syntax above a function definition.
    At this layer decorators carry **no security interpretation** --
    they record what was written, not what it means.  Security meaning
    is assigned by Layer 2 interpreters.

    Example::

        for dec in fn.decorators:
            print(dec.name)  # "app.route"
            print(dec.fqn)  # resolved FQN or None
            print(dec.arguments)  # ("/users", 'methods=["POST"]')
    """

    name: str
    """Short name of the decorator as written in source (e.g. ``"app.route"``)."""

    fqn: str | None
    """Fully qualified name if resolved, or ``None``."""

    arguments: tuple[str, ...]
    """Decorator arguments as source-text strings."""

    location: Location
    """Source location of the ``@`` token."""

    def __repr__(self) -> str:
        call = f"@{self.name}"
        if self.arguments:
            call += f"({', '.join(self.arguments)})"
        return f"Decorator({call}, {_short_loc(self.location)})"


@dataclass(frozen=True)
class OverloadSignature:
    """One ``@overload`` stub signature of an overloaded function.

    The implementation signature lives on :attr:`Function.params`; each
    instance here is a ``typing.overload`` stub declaration carrying its
    own parameter annotations -- e.g. a selector parameter narrowed to
    ``Literal[True]`` / ``Literal[False]``.  Exposing the stubs lets a
    rule reason about which behavior a given argument selects, rather than
    seeing only the merged implementation signature.

    Layer 1 does not capture return annotations, so an overload's return
    type is not represented here yet -- only its parameters.
    """

    params: tuple[Parameter, ...]
    """Parameters of this overload stub, in declaration order."""

    location: Location
    """Source location of the ``@overload`` stub definition."""

    def __repr__(self) -> str:
        params = ", ".join(repr(parameter) for parameter in self.params)
        return f"OverloadSignature(({params}), {_short_loc(self.location)})"


@dataclass(frozen=True)
class Function:
    """A Python function, method, nested function, or lambda.

    Created by Layer 1 (Code Index) during AST traversal.  Not
    directly constructable by rule authors -- obtained from
    :attr:`~flawed.repo.RepoView.functions` or by navigating
    from a :class:`~flawed.route.Route`.

    The ``parent_class`` / ``parent_function`` fields establish the
    nesting hierarchy: a method has ``parent_class`` set; a nested
    function or closure has ``parent_function`` set; a top-level
    function has both as ``None``.

    Source file and line are available via ``fn.location.file`` and
    ``fn.location.line``.

    Example::

        fn = kb.functions.named("create_user").one()
        print(fn.location.file)  # "app/views.py"
        for param in fn.params:
            print(param.name)
        for callee in fn.calls:
            print(callee.fqn)
    """

    fqn: str
    """Fully qualified name (e.g. ``"myapp.views.create_user"``)."""

    name: str
    """Short name (e.g. ``"create_user"``)."""

    params: tuple[Parameter, ...]
    """Parameters in declaration order."""

    kind: FunctionKind
    """Structural classification (top-level, method, nested, lambda, closure)."""

    parent_class: str | None
    """FQN of the enclosing class, or ``None`` for non-methods."""

    parent_function: str | None
    """FQN of the enclosing function, or ``None`` for top-level / methods."""

    location: Location
    """Source location spanning the entire function definition."""

    provenance: Provenance
    """Which analysis pass discovered this function."""

    overloads: tuple[OverloadSignature, ...] = ()
    """``@overload`` stub signatures when this function is overloaded; ``()``
    otherwise.  :attr:`params` remains the implementation signature, while each
    entry here is one ``typing.overload`` stub with its own parameter
    annotations (e.g. a selector narrowed to ``Literal[True]`` /
    ``Literal[False]``).  See :class:`OverloadSignature`."""

    def __repr__(self) -> str:
        params = ", ".join(parameter.name for parameter in self.params)
        return (
            f"Function({self.name}({params}), {self.kind.name.lower()}, "
            f"{_short_loc(self.location)})"
        )

    @property
    def decorators(self) -> DecoratorCollection:
        """Decorators applied to this function."""
        raise RuntimeError("Function.decorators requires Semantic Layer context")

    @property
    def body(self) -> CodeScope:
        """Direct function body as a queryable scope.

        Returns a :class:`~flawed.scopes.CodeScope` covering only
        statements inside this function, excluding transitively called
        functions.
        """
        raise RuntimeError("Function.body requires Semantic Layer context")

    @property
    def reachable(self) -> CodeScope:
        """Transitively reachable code from this function.

        Includes the function body plus all functions called directly or
        indirectly.  Use for queries like "does any code reachable from
        this handler write to the database?"
        """
        raise RuntimeError("Function.reachable requires Semantic Layer context")

    @property
    def called_by(self) -> FunctionCollection:
        """Functions that call this function (callers)."""
        raise RuntimeError("Function.called_by requires Semantic Layer context")

    @property
    def calls(self) -> FunctionCollection:
        """Functions called by this function (callees)."""
        raise RuntimeError("Function.calls requires Semantic Layer context")

    def parameter_named(self, name: str) -> Parameter:
        """Look up a parameter by name.

        Raises ``KeyError`` if no parameter with the given name exists.
        """
        for parameter in self.params:
            if parameter.name == name:
                return parameter
        raise KeyError(name)

    @property
    def gaps(self) -> tuple[AnalysisGap, ...]:
        """Analysis gaps affecting this function.

        Automatically populated by Layer 2 from Layer 1 extraction
        errors (CFG failures, unresolved symbols, etc.).  Rule authors
        do not need to check this -- gaps propagate into findings
        automatically.
        """
        raise RuntimeError("Function.gaps requires Semantic Layer context")

    def source(self, context: int = 3) -> str:
        """Return source text with surrounding context lines.

        Args:
            context: Number of lines before and after to include.
        """
        from flawed.flow import _get_private

        repo_path = _get_private(self, "_repo_path")
        if not isinstance(repo_path, str):
            return f"<source unavailable: {self.location.file}:{self.location.line}>"
        file_path = Path(repo_path) / self.location.file
        try:
            lines = file_path.read_text().splitlines()
        except (OSError, UnicodeDecodeError):
            return f"<source unavailable: {self.location.file}:{self.location.line}>"
        start = max(0, self.location.line - 1 - context)
        end_line = (
            self.location.end_line if self.location.end_line is not None else self.location.line
        )
        end = min(len(lines), end_line + context)
        return "\n".join(lines[start:end])
