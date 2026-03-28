"""Specs: class discovery, filtering, and hierarchy.

Fixture: tests/fixtures/apps/classes/ (session-scoped via root conftest)
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from flawed.repo import RepoView


class TestClassDiscovery:
    def test_discovers_all_classes(self, classes_app: RepoView) -> None:
        names = {c.name for c in classes_app.classes}
        assert names >= {"Base", "Timestamped", "User", "Admin", "Serializable", "APIUser"}

    def test_named_filter(self, classes_app: RepoView) -> None:
        assert classes_app.classes.named("User").one().name == "User"

    def test_with_fqn_filter(self, classes_app: RepoView) -> None:
        """with_fqn() locates a class by its fully-qualified name."""
        matches = classes_app.classes.with_fqn("models.Admin")
        assert len(matches) == 1
        assert matches.one().name == "Admin"

    def test_in_file_filter(self, classes_app: RepoView) -> None:
        """in_file() restricts to classes defined in a single module."""
        classes = classes_app.classes.in_file("models.py")
        assert len(classes) == 6

    def test_subclasses_of_transitive(self, classes_app: RepoView) -> None:
        subs = classes_app.classes.subclasses_of("Base")
        names = {c.name for c in subs}
        # User extends Base, Admin extends User, APIUser extends User
        assert names >= {"User", "Admin", "APIUser"}

    def test_direct_subclasses_of(self, classes_app: RepoView) -> None:
        direct = classes_app.classes.direct_subclasses_of("Base")
        names = {c.name for c in direct}
        assert "User" in names
        assert "Admin" not in names  # Admin extends User, not Base directly

    def test_is_abstract(self, classes_app: RepoView) -> None:
        """Abstract base classes are flagged via is_abstract."""
        serializable = classes_app.classes.named("Serializable").one()
        assert serializable.is_abstract is True

        user = classes_app.classes.named("User").one()
        assert user.is_abstract is False


class TestClassHierarchy:
    def test_mro(self, classes_app: RepoView) -> None:
        api_user = classes_app.classes.named("APIUser").one()
        mro_names = [c for c in api_user.mro]
        # APIUser -> Serializable -> User -> Timestamped -> Base -> object
        assert "APIUser" in mro_names[0] or api_user.name in mro_names[0]

    def test_full_mro_order(self, classes_app: RepoView) -> None:
        """MRO follows Python C3 linearization order."""
        api_user = classes_app.classes.named("APIUser").one()
        # Expected: APIUser, Serializable, User, Timestamped, Base, object
        mro_short = [m.rsplit(".", 1)[-1] for m in api_user.mro]
        assert mro_short.index("Serializable") < mro_short.index("User")
        assert mro_short.index("User") < mro_short.index("Base")
        assert mro_short.index("object") == len(mro_short) - 1

    def test_bases(self, classes_app: RepoView) -> None:
        user = classes_app.classes.named("User").one()
        base_names = [b for b in user.bases]
        assert any("Timestamped" in b for b in base_names)
        assert any("Base" in b for b in base_names)

    def test_methods(self, classes_app: RepoView) -> None:
        user = classes_app.classes.named("User").one()
        assert "__init__" in user.method_names
        assert "greet" in user.method_names

    def test_methods_as_collection(self, classes_app: RepoView) -> None:
        """Class.methods returns a FunctionCollection of directly defined methods."""
        user = classes_app.classes.named("User").one()
        method_names = {m.name for m in user.methods}
        assert method_names == {"__init__", "greet"}

    def test_inherited_methods(self, classes_app: RepoView) -> None:
        admin = classes_app.classes.named("Admin").one()
        inherited = {m.name for m in admin.inherited_methods}
        assert "save" in inherited  # from Base
        assert "greet" in inherited  # from User
        assert "touch" in inherited  # from Timestamped

    def test_inherited_method_defining_class(self, classes_app: RepoView) -> None:
        """InheritedMethod tracks which class originally defined the method."""
        admin = classes_app.classes.named("Admin").one()
        by_name = {m.name: m.defining_class for m in admin.inherited_methods}
        assert "Timestamped" in by_name["touch"]
        assert "Base" in by_name["save"]
        assert "User" in by_name["greet"]
