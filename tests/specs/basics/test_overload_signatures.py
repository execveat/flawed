"""Specs: ``@overload`` stub signatures preserved on the typed Function surface.

Regression coverage for FLAW-265.  Layer 1 emits one ``FunctionRecord`` per
``def`` (including each ``@overload`` stub); a naive last-wins FQN projection in
Layer 2 collapsed them to the implementation signature only, silently dropping
the stub signatures.  A selector parameter narrowed to ``Literal[True]`` /
``Literal[False]`` was therefore invisible to any overload-reasoning rule -- a
false negative.  These specs pin that the stub signatures are now exposed via
:attr:`flawed.function.Function.overloads`.

Fixture: ``tests/fixtures/apps/overload_signatures/overload_signatures.py`` --
``load_account`` has two ``@overload`` stubs (``Literal[True]`` /
``Literal[False]``) plus the ``bool`` implementation.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from flawed.repo import RepoView


class TestOverloadSignatures:
    """The typed ``Function`` surface exposes ``@overload`` stub signatures."""

    def test_overload_stub_signatures_preserved(self, overload_signatures: RepoView) -> None:
        fn = overload_signatures.functions.named("load_account").one()

        # The implementation signature still lives on params.
        assert fn.parameter_named("include_private").annotation == "bool"

        # Both @overload stub signatures are now visible.
        assert len(fn.overloads) == 2
        selector_annotations = {overload.params[1].annotation for overload in fn.overloads}
        assert selector_annotations == {"Literal[True]", "Literal[False]"}

        # Each overload carries its own source location (the stub def).
        for overload in fn.overloads:
            assert overload.location.file.endswith("overload_signatures.py")

    def test_non_overloaded_function_has_no_overloads(self, overload_signatures: RepoView) -> None:
        fn = overload_signatures.functions.named("bool_overload").one()
        assert fn.overloads == ()
