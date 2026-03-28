"""Verify selector construction and composability."""

from __future__ import annotations


class TestEffectSelector:
    def test_mutation_any(self) -> None:
        from flawed.effects import EffectCategory, Mutation

        sel = Mutation.any()
        assert EffectCategory.DB_WRITE in sel.categories
        assert EffectCategory.DB_DELETE in sel.categories
        assert EffectCategory.FILE_WRITE in sel.categories
        assert EffectCategory.CACHE_WRITE in sel.categories
        assert EffectCategory.STATE_WRITE in sel.categories
        assert EffectCategory.CONFIG_WRITE in sel.categories
        assert EffectCategory.RESPONSE_WRITE in sel.categories
        assert sel.key_filter is None

    def test_mutation_write(self) -> None:
        from flawed.effects import EffectCategory, Mutation

        sel = Mutation.write()
        assert EffectCategory.DB_WRITE in sel.categories
        assert EffectCategory.FILE_WRITE in sel.categories
        assert EffectCategory.CACHE_WRITE in sel.categories
        assert EffectCategory.STATE_WRITE in sel.categories
        assert EffectCategory.CONFIG_WRITE in sel.categories
        assert EffectCategory.RESPONSE_WRITE in sel.categories

    def test_mutation_persistent(self) -> None:
        from flawed.effects import EffectCategory, Mutation

        sel = Mutation.persistent()
        # Persistent state changes: any() MINUS the ephemeral response write.
        assert sel.categories == frozenset(
            {
                EffectCategory.DB_WRITE,
                EffectCategory.DB_DELETE,
                EffectCategory.FILE_WRITE,
                EffectCategory.CACHE_WRITE,
                EffectCategory.STATE_WRITE,
                EffectCategory.CONFIG_WRITE,
            }
        )
        assert EffectCategory.RESPONSE_WRITE not in sel.categories
        # Pinned to any() so a future mutation category is inherited automatically.
        assert sel.categories == Mutation.any().categories - {EffectCategory.RESPONSE_WRITE}
        assert sel.key_filter is None

    def test_mutation_delete(self) -> None:
        from flawed.effects import EffectCategory, Mutation

        sel = Mutation.delete()
        assert sel.categories == frozenset({EffectCategory.DB_DELETE})

    def test_db_write(self) -> None:
        from flawed.effects import Db, EffectCategory

        sel = Db.write()
        assert sel.categories == frozenset({EffectCategory.DB_WRITE})

    def test_db_any(self) -> None:
        from flawed.effects import Db, EffectCategory

        sel = Db.any()
        assert EffectCategory.DB_WRITE in sel.categories
        assert EffectCategory.DB_DELETE in sel.categories
        assert EffectCategory.DB_READ in sel.categories

    def test_data_write(self) -> None:
        from flawed.effects import Data, EffectCategory

        sel = Data.write()
        assert sel.categories == frozenset(
            {EffectCategory.DB_WRITE, EffectCategory.FILE_WRITE, EffectCategory.CACHE_WRITE}
        )

    def test_data_read(self) -> None:
        from flawed.effects import Data, EffectCategory

        sel = Data.read()
        assert sel.categories == frozenset(
            {EffectCategory.DB_READ, EffectCategory.FILE_READ, EffectCategory.CACHE_READ}
        )

    def test_state_write(self) -> None:
        from flawed.effects import EffectCategory, State

        sel = State.write()
        assert sel.categories == frozenset({EffectCategory.STATE_WRITE})
        assert sel.key_filter is None
        assert sel.scope_filter is None

    def test_state_write_with_scope(self) -> None:
        from flawed.effects import State, StateScope

        sel = State.write(scope=StateScope.SESSION)
        assert sel.scope_filter == StateScope.SESSION

    def test_state_write_with_combined_scope(self) -> None:
        from flawed.effects import State, StateScope

        sel = State.write(scope=StateScope.SESSION | StateScope.SERVER)
        assert sel.scope_filter is not None
        assert StateScope.SESSION in sel.scope_filter
        assert StateScope.SERVER in sel.scope_filter

    def test_state_write_with_key(self) -> None:
        from flawed.effects import State

        sel = State.write(key="user_id")
        assert sel.key_filter == frozenset({"user_id"})

    def test_state_read(self) -> None:
        from flawed.effects import EffectCategory, State

        sel = State.read()
        assert sel.categories == frozenset({EffectCategory.STATE_READ})

    def test_config_write(self) -> None:
        from flawed.effects import Config, EffectCategory

        sel = Config.write()
        assert sel.categories == frozenset({EffectCategory.CONFIG_WRITE})

    def test_outbound_request(self) -> None:
        from flawed.effects import EffectCategory, Outbound

        # Default breadth: both user-targetable and configured-target outbounds
        # (FLAW-276) -- timeout/coverage rules want every outbound HTTP call.
        sel = Outbound.request()
        assert sel.categories == frozenset(
            {EffectCategory.OUTBOUND_REQUEST, EffectCategory.OUTBOUND_REQUEST_CONFIGURED}
        )
        # SSRF rules narrow to caller-influenced targets only.
        ssrf_sel = Outbound.request(user_controllable_target=True)
        assert ssrf_sel.categories == frozenset({EffectCategory.OUTBOUND_REQUEST})

    def test_or_composition(self) -> None:
        from flawed.effects import EffectCategory, Mutation, State

        combined = Mutation.any() | State.write()
        assert EffectCategory.DB_WRITE in combined.categories
        assert EffectCategory.DB_DELETE in combined.categories
        assert EffectCategory.STATE_WRITE in combined.categories
        assert combined.key_filter is None

    def test_or_composition_multiple(self) -> None:
        from flawed.effects import (
            EffectCategory,
            Mutation,
            Outbound,
            State,
        )

        combined = Mutation.write() | State.write() | Outbound.request()
        assert EffectCategory.DB_WRITE in combined.categories
        assert EffectCategory.STATE_WRITE in combined.categories
        assert EffectCategory.OUTBOUND_REQUEST in combined.categories

    def test_or_is_a_new_selector(self) -> None:
        from flawed.effects import Mutation, State

        a = Mutation.write()
        b = State.write()
        combined = a | b
        assert combined is not a
        assert combined is not b
        # Originals unchanged (frozen)
        # DB_WRITE, FILE_WRITE, CACHE_WRITE, STATE_WRITE, CONFIG_WRITE, RESPONSE_WRITE
        assert len(a.categories) == 6
        assert len(b.categories) == 1

    def test_or_key_filter_merge(self) -> None:
        """When both sides have key_filter, they merge as frozenset union."""
        from flawed.effects import State

        a = State.write(key="email")
        b = State.write(key="role")
        combined = a | b
        assert combined.key_filter == frozenset({"email", "role"})

    def test_or_key_filter_wildcard(self) -> None:
        """When one side is wildcard (None), result is wildcard."""
        from flawed.effects import Mutation, State

        a = Mutation.write()  # key_filter=None (wildcard)
        b = State.write(key="email")
        combined = a | b
        assert combined.key_filter is None

    def test_response_write(self) -> None:
        from flawed.effects import EffectCategory, Response

        sel = Response.write()
        assert sel.categories == frozenset({EffectCategory.RESPONSE_WRITE})
        assert sel.key_filter is None

    def test_response_write_with_key(self) -> None:
        from flawed.effects import Response

        sel = Response.write(key="cookie:session_id")
        assert sel.key_filter == frozenset({"cookie:session_id"})

    def test_cache_write(self) -> None:
        from flawed.effects import Cache, EffectCategory

        sel = Cache.write()
        assert sel.categories == frozenset({EffectCategory.CACHE_WRITE})

    def test_cache_read(self) -> None:
        from flawed.effects import Cache, EffectCategory

        sel = Cache.read()
        assert sel.categories == frozenset({EffectCategory.CACHE_READ})

    def test_cache_any(self) -> None:
        from flawed.effects import Cache, EffectCategory

        sel = Cache.any()
        assert sel.categories == frozenset({EffectCategory.CACHE_WRITE, EffectCategory.CACHE_READ})

    def test_cache_write_with_key(self) -> None:
        from flawed.effects import Cache

        sel = Cache.write(key="user:42")
        assert sel.key_filter == frozenset({"user:42"})


class TestFnSelector:
    def test_named(self) -> None:
        from flawed.calls import Fn

        sel = Fn.named("save")
        assert sel.name_filter == "save"
        assert sel.fqn_filter is None
        assert sel.pattern_filter == ()

    def test_fqn(self) -> None:
        from flawed.calls import Fn

        sel = Fn.fqn("app.models.User.save")
        assert sel.fqn_filter == "app.models.User.save"
        assert sel.name_filter is None

    def test_matching(self) -> None:
        from flawed.calls import Fn

        sel = Fn.matching(r"auth.*")
        assert sel.pattern_filter == (r"auth.*",)

    def test_or_composition(self) -> None:
        from flawed.calls import Fn

        a = Fn.named("save")
        b = Fn.fqn("app.models.User.save")
        combined = a | b
        assert combined is not a
        assert combined is not b
        assert len(combined._alternatives) == 2
        assert combined._alternatives[0].name_filter == "save"
        assert combined._alternatives[1].fqn_filter == "app.models.User.save"

    def test_or_composition_multiple(self) -> None:
        from flawed.calls import Fn

        combined = Fn.named("a") | Fn.fqn("b.c") | Fn.matching(r"d.*")
        assert len(combined._alternatives) == 3

    def test_or_preserves_originals(self) -> None:
        from flawed.calls import Fn

        a = Fn.named("save")
        b = Fn.fqn("app.save")
        _ = a | b
        # Originals unchanged (frozen)
        assert a.name_filter == "save"
        assert a._alternatives == ()
        assert b.fqn_filter == "app.save"
        assert b._alternatives == ()


class TestCheckSelectors:
    def test_crypto_compare_is_composite(self) -> None:
        from flawed.checks import Crypto

        sel = Crypto.compare()
        assert len(sel._alternatives) >= 3

    def test_crypto_compare_matches_flask_bcrypt_instance_method(self) -> None:
        """Flask-Bcrypt's ``bcrypt.check_password_hash(...)`` is an instance
        method on a ``Bcrypt()`` object, so it has no resolvable library FQN.
        ``Crypto.compare()`` must still recognize it by name/expression
        (FLAW-174) so credential-check consumers (g016, r02e/u004, ...) see it.
        """
        from flawed.checks import Crypto

        sel = Crypto.compare()
        # Instance method: short name resolves, FQN does not.
        assert sel.matches_values(
            name="check_password_hash",
            fqn=None,
            expression="bcrypt.check_password_hash",
        )

    def test_crypto_compare_matches_argon2_and_passlib_verify_password(self) -> None:
        """argon2 / passlib ``verify_password`` recognized by name even when the
        import doesn't resolve to the ``argon2.verify_password`` FQN (FLAW-174)."""
        from flawed.checks import Crypto

        sel = Crypto.compare()
        assert sel.matches_values(
            name="verify_password", fqn=None, expression="ph.verify_password"
        )

    def test_crypto_compare_still_matches_library_fqns(self) -> None:
        """Regression guard: the precise library FQNs keep matching."""
        from flawed.checks import Crypto

        sel = Crypto.compare()
        for fqn in (
            "hmac.compare_digest",
            "werkzeug.security.check_password_hash",
            "bcrypt.checkpw",
            "argon2.verify_password",
        ):
            assert sel.matches_values(name=fqn.rsplit(".", 1)[-1], fqn=fqn), fqn

    def test_crypto_compare_does_not_match_unrelated_verify(self) -> None:
        """Precision guard: a bare ``.verify()`` (e.g. signature/cert/mock) is
        NOT a credential comparison and must not match — adding bare ``verify``
        would over-broaden the selector and silently suppress real findings in
        the dominance consumers."""
        from flawed.checks import Crypto

        sel = Crypto.compare()
        assert not sel.matches_values(name="verify", fqn=None, expression="cert.verify")
        assert not sel.matches_values(name="validate", fqn=None, expression="schema.validate")

    def test_crypto_compare_matches_hasher_verify_fqns(self) -> None:
        """FLAW-182: the argon2-cffi / passlib hasher ``.verify(hash, pw)`` idiom
        is recognized via a *curated FQN allowlist* (not a bare ``verify`` name,
        which stays excluded — see ``test_crypto_compare_does_not_match_unrelated_verify``).

        ``passlib.hash.argon2.verify`` is a module-level handler call whose FQN
        resolves directly today; the instance forms (``argon2.PasswordHasher.verify``,
        ``passlib.context.CryptContext.verify``) fire once L2 receiver-type
        resolution binds the instance to its hasher class (FLAW-116)."""
        from flawed.checks import Crypto

        sel = Crypto.compare()
        for fqn in (
            "passlib.hash.argon2.verify",
            "argon2.PasswordHasher.verify",
            "passlib.context.CryptContext.verify",
        ):
            assert sel.matches_values(name="verify", fqn=fqn), fqn

    def test_crypto_compare_hasher_verify_does_not_over_match(self) -> None:
        """Precision guard for FLAW-182: an instance ``.verify`` whose FQN is NOT
        a curated credential hasher (or does not resolve at all) must not match —
        the allowlist is keyed on the precise hasher FQN, never the bare name."""
        from flawed.checks import Crypto

        sel = Crypto.compare()
        # Unresolved instance .verify (no receiver-type) — not matched.
        assert not sel.matches_values(name="verify", fqn=None, expression="ph.verify")
        # A resolved-but-unrelated .verify (JWT / signature library) — not matched.
        assert not sel.matches_values(name="verify", fqn="jwt.PyJWS.verify")

    def test_token_verify_is_composite(self) -> None:
        from flawed.checks import Token

        sel = Token.verify()
        assert len(sel._alternatives) >= 3

    def test_schema_validate_is_composite(self) -> None:
        from flawed.checks import Schema

        sel = Schema.validate()
        assert len(sel._alternatives) >= 4

    def test_permission_check_uses_pattern(self) -> None:
        from flawed.checks import Permission

        sel = Permission.check()
        assert sel.pattern_filter is not None

    def test_cross_compose_checks_and_effects(self) -> None:
        """Checks and effects are different types; this just verifies
        they can be constructed together without errors."""
        from flawed.checks import Crypto, Token
        from flawed.effects import Mutation, State

        validators = Crypto.compare() | Token.verify()
        sensitive = Mutation.any() | State.write()
        assert validators._alternatives
        assert sensitive.categories


class TestStrNormalizationSelectors:
    """FLAW-179: string-normalization transform vocabulary.

    String normalizers (lower / casefold / strip / unicode normalize) are the
    transforms that canonicalize a value before comparison or lookup.  They
    matter for value-flow comparison: when one code path normalizes a value
    (e.g. lowercases an email claim) and another does not, the two interpret
    "the same" input differently.
    """

    def test_case_fold_matches_lower_and_casefold(self) -> None:
        from flawed.checks import Str

        sel = Str.case_fold()
        # str methods bind through an instance -> no FQN, matched by short name.
        assert sel.matches_values(name="lower", fqn=None, expression="email.lower")
        assert sel.matches_values(name="casefold", fqn=None, expression="s.casefold")

    def test_case_fold_does_not_match_unrelated(self) -> None:
        """Precision: the pattern is anchored, so partial names do not match."""
        from flawed.checks import Str

        sel = Str.case_fold()
        assert not sel.matches_values(name="strip", fqn=None)
        assert not sel.matches_values(name="lowercase", fqn=None)
        assert not sel.matches_values(name="lower_bound", fqn=None)

    def test_strip_matches_all_strip_variants(self) -> None:
        from flawed.checks import Str

        sel = Str.strip()
        for name in ("strip", "lstrip", "rstrip"):
            assert sel.matches_values(name=name, fqn=None), name

    def test_strip_does_not_match_unrelated(self) -> None:
        from flawed.checks import Str

        sel = Str.strip()
        assert not sel.matches_values(name="split", fqn=None)
        assert not sel.matches_values(name="stripe", fqn=None)

    def test_unicode_normalize_matches_resolved_fqn(self) -> None:
        from flawed.checks import Str

        sel = Str.unicode_normalize()
        # Both `unicodedata.normalize(...)` and `from unicodedata import normalize`
        # resolve to this FQN through L1 import resolution.
        assert sel.matches_values(name="normalize", fqn="unicodedata.normalize")

    def test_unicode_normalize_does_not_match_bare_normalize(self) -> None:
        """Precision: a bare ``normalize`` (schema / path / model normalizer)
        is NOT unicode normalization -- only the resolved ``unicodedata.normalize``
        FQN matches.  Matching the bare name would over-broaden the selector."""
        from flawed.checks import Str

        sel = Str.unicode_normalize()
        assert not sel.matches_values(name="normalize", fqn="marshmallow.Schema.normalize")
        assert not sel.matches_values(name="normalize", fqn=None, expression="schema.normalize")

    def test_normalize_is_aggregate_of_all_kinds(self) -> None:
        from flawed.checks import Str

        sel = Str.normalize()
        assert sel.matches_values(name="lower", fqn=None)
        assert sel.matches_values(name="casefold", fqn=None)
        assert sel.matches_values(name="strip", fqn=None)
        assert sel.matches_values(name="rstrip", fqn=None)
        assert sel.matches_values(name="normalize", fqn="unicodedata.normalize")

    def test_normalize_rejects_non_normalizers(self) -> None:
        from flawed.checks import Str

        sel = Str.normalize()
        assert not sel.matches_values(name="encode", fqn=None)
        assert not sel.matches_values(name="format", fqn=None)
        assert not sel.matches_values(name="normalize", fqn="schema.normalize")

    def test_str_composes_with_other_check_vocab(self) -> None:
        """Str selectors are FnSelectors and compose with the rest of the
        checks vocabulary via ``|``."""
        from flawed.checks import Crypto, Str

        combined = Str.case_fold() | Crypto.compare()
        assert combined._alternatives
        assert combined.matches_values(name="lower", fqn=None)
        assert combined.matches_values(name="check_password_hash", fqn=None)


class TestAccepting:
    def test_accepting_predicate(self) -> None:
        from flawed.core import (
            Location,
            Provenance,
        )
        from flawed.function import Function, FunctionKind
        from flawed.route import (
            HttpMethod,
            Route,
            accepting,
        )

        loc = Location(file="a.py", line=1, column=0)
        prov = Provenance(
            source_layer="L2",
            interpreter="test",
            confidence=1.0,
            supporting_facts=(),
        )
        handler = Function(
            fqn="app.views.index",
            name="index",
            params=(),
            kind=FunctionKind.TOP_LEVEL,
            parent_class=None,
            parent_function=None,
            location=loc,
            provenance=Provenance(
                source_layer="L1",
                interpreter="ast",
                confidence=1.0,
            ),
        )
        route = Route(
            endpoint="index",
            url_rule="/",
            methods=frozenset({HttpMethod.GET, HttpMethod.POST}),
            handler=handler,
            group=None,
            location=loc,
            provenance=prov,
        )

        assert accepting(HttpMethod.GET)(route) is True
        assert accepting(HttpMethod.POST)(route) is True
        assert accepting(HttpMethod.DELETE)(route) is False
        assert accepting(HttpMethod.GET, HttpMethod.DELETE)(route) is True
