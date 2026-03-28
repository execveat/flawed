"""Fixture exercising ``@overload`` stub-signature extraction (FLAW-265).

Layer 1 emits one ``FunctionRecord`` per ``def``, including each ``@overload``
stub.  ``load_account`` carries two stubs whose selector parameter narrows to
``Literal[True]`` / ``Literal[False]`` plus the ``bool`` implementation, so the
typed ``Function`` surface can expose the stub signatures.  ``bool_overload`` is
an ordinary, non-overloaded function used as the negative case.
"""

from __future__ import annotations

from typing import Literal, overload


@overload
def load_account(user_id: str, include_private: Literal[True]) -> dict[str, object]: ...


@overload
def load_account(user_id: str, include_private: Literal[False]) -> dict[str, str]: ...


def load_account(user_id: str, include_private: bool) -> dict[str, object]:
    account: dict[str, object] = {"id": user_id}
    if include_private:
        account["private"] = True
    return account


def bool_overload(user_id: str, include_private: bool) -> dict[str, object]:
    return load_account(user_id, include_private)
