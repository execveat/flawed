"""Composable selectors for security-relevant validation functions.

Parallel to the effects module: where effects describe *what side
effects occur*, checks describe *what validation functions are called*.
Use checks to determine whether a route validates its inputs before
performing a sensitive operation.

The selector namespaces are:

- :class:`Crypto` -- cryptographic comparison and hashing
- :class:`Token` -- JWT / signed-token verification
- :class:`Schema` -- input schema validation (pydantic, marshmallow, etc.)
- :class:`Permission` -- authorization / permission checks (heuristic)
- :class:`Str` -- string-normalization transforms (lower / strip / unicode)

Compose checks with effects to express security patterns::

    from flawed.checks import Crypto, Token, Schema, Permission
    from flawed.calls import Fn
    from flawed.effects import Mutation, State

    VALIDATORS = Crypto.compare() | Token.verify()
    SENSITIVE = Mutation.any() | State.write()

    validators = route.reachable.calls(VALIDATORS).with_argument_from(read.value)

Permission selectors use name-pattern matching (heuristic) since
authorization functions are project-specific.  Extend with
``Fn.fqn()`` for precision when the target project's auth functions
are known.
"""

from __future__ import annotations

from flawed.calls import Fn, FnSelector


class Crypto:
    """Selectors for cryptographic verification functions.

    Example::

        Crypto.compare()  # hmac.compare_digest, check_password_hash, etc.
        Crypto.hash()  # hashlib.sha256, hashlib.pbkdf2_hmac, etc.
    """

    @staticmethod
    def compare() -> FnSelector:
        """Hash/digest comparison functions.

        Matches the precise library FQNs ``hmac.compare_digest``,
        ``werkzeug.security.check_password_hash``, ``bcrypt.checkpw``,
        ``passlib.hash.bcrypt.verify``, ``argon2.verify_password`` -- *plus* a
        name-pattern arm for the password-comparison idioms that bind through an
        instance and therefore have no resolvable library FQN:

        - Flask-Bcrypt ``bcrypt.check_password_hash(...)`` where ``bcrypt`` is a
          ``Bcrypt(app)`` instance (short name ``check_password_hash``);
        - explicit ``verify_password`` (argon2 / passlib helpers) however imported;
        - ``check_password`` / ``checkpw`` / ``compare_digest`` reached via a
          re-export or alias the FQN filter would miss.

        The name-pattern arm is deliberately restricted to *password-specific*
        names.  A bare ``verify`` / ``validate`` is intentionally excluded: it is
        too generic (signature, certificate, mock, schema verification) and
        over-matching here would silently suppress real findings in the
        credential-check *dominance* consumers, which gate purely on
        the presence of a credential comparison.  This mirrors the heuristic
        name-pattern approach already used by :meth:`Token.is_valid` and
        :class:`Permission` for idioms that are not library-FQN-addressable.

        The argon2-cffi / passlib ``hasher.verify(hash, pw)`` idiom (FLAW-182) is
        recognized through a *curated hasher-FQN allowlist* rather than the bare
        ``verify`` name, preserving the precision guarantee above:

        - ``passlib.hash.argon2.verify`` -- a module-level handler call whose FQN
          resolves directly today (sibling of the existing ``passlib.hash.bcrypt.verify``);
        - ``argon2.PasswordHasher.verify`` / ``passlib.context.CryptContext.verify``
          -- the instance-method forms; these fire once L2 receiver-type
          resolution binds the instance to its hasher class (FLAW-116).  Listing
          the precise class FQN (not the bare ``verify`` name) is what keeps an
          unrelated ``cert.verify`` / ``jwt.verify`` from matching.
        """
        return (
            Fn.fqn("hmac.compare_digest")
            | Fn.fqn("werkzeug.security.check_password_hash")
            | Fn.fqn("bcrypt.checkpw")
            | Fn.fqn("passlib.hash.bcrypt.verify")
            | Fn.fqn("passlib.hash.argon2.verify")
            | Fn.fqn("argon2.verify_password")
            | Fn.fqn("argon2.PasswordHasher.verify")
            | Fn.fqn("passlib.context.CryptContext.verify")
            | Fn.matching(
                r"^(check_password_hash|check_password|checkpw|verify_password|compare_digest)$"
            )
        )

    @staticmethod
    def hash() -> FnSelector:
        """Cryptographic hash construction functions.

        Matches: ``hashlib.sha256``, ``hashlib.sha512``, ``hashlib.sha384``,
        ``hashlib.sha3_256``, ``hashlib.pbkdf2_hmac``, ``hashlib.scrypt``.
        """
        return (
            Fn.fqn("hashlib.sha256")
            | Fn.fqn("hashlib.sha512")
            | Fn.fqn("hashlib.sha384")
            | Fn.fqn("hashlib.sha3_256")
            | Fn.fqn("hashlib.pbkdf2_hmac")
            | Fn.fqn("hashlib.scrypt")
        )


class Token:
    """Selectors for token verification functions.

    Example::

        Token.verify()  # jwt.decode, itsdangerous loads, etc.
    """

    @staticmethod
    def verify() -> FnSelector:
        """Token decode / verification functions.

        Matches: ``jwt.decode``, ``jose.jwt.decode``, ``authlib.jose.jwt.decode``,
        ``itsdangerous.URLSafeTimedSerializer.loads``,
        ``itsdangerous.URLSafeSerializer.loads``, ``itsdangerous.Signer.unsign``.
        """
        return (
            Fn.fqn("jwt.decode")
            | Fn.fqn("jose.jwt.decode")
            | Fn.fqn("authlib.jose.jwt.decode")
            | Fn.fqn("itsdangerous.URLSafeTimedSerializer.loads")
            | Fn.fqn("itsdangerous.URLSafeSerializer.loads")
            | Fn.fqn("itsdangerous.Signer.unsign")
        )

    @staticmethod
    def is_valid() -> FnSelector:
        """Validity-check methods on a resolved credential / principal record.

        The library-specific decoders in :meth:`verify` only cover signed
        tokens.  Many credentials are validated by a method on the record that
        a lookup resolved -- ``record.is_valid()``, ``token.is_active()``,
        ``key.check_token()`` -- after a database lookup confirms the credential
        exists.  This is the validity step that distinguishes a *validated*
        derivation from a presence-only one.

        Name-pattern matching (heuristic), mirroring :class:`Permission`, because
        these methods are project-specific rather than library-defined.  Matches
        short names ``is_valid``, ``is_active``, ``verify``, ``validate``,
        ``check_token``.
        """
        return Fn.matching(r"^(is_valid|is_active|verify|validate|check_token)$")


class Schema:
    """Selectors for schema / input validation functions.

    Example::

        Schema.validate()  # pydantic, marshmallow, wtforms, cerberus, etc.
    """

    @staticmethod
    def validate() -> FnSelector:
        """Schema validation functions.

        Matches: ``pydantic.BaseModel.model_validate``,
        ``marshmallow.Schema.load``, ``wtforms.Form.validate``,
        ``cerberus.Validator.validate``, ``voluptuous.Schema.__call__``,
        and their common variants.
        """
        return (
            Fn.fqn("pydantic.BaseModel.model_validate")
            | Fn.fqn("pydantic.BaseModel.model_validate_json")
            | Fn.fqn("marshmallow.Schema.load")
            | Fn.fqn("marshmallow.Schema.loads")
            | Fn.fqn("wtforms.Form.validate")
            | Fn.fqn("wtforms.Form.validate_on_submit")
            | Fn.fqn("cerberus.Validator.validate")
            | Fn.fqn("voluptuous.Schema.__call__")
        )


class Permission:
    """Selectors for authorization / permission check functions.

    These use name matching (heuristic) since permission check
    functions are project-specific.  Extend with ``Fn.fqn()`` for
    precision when the target project's auth functions are known.

    Example::

        Permission.check()  # has_permission, authorize, etc.
        Permission.require()  # require_permission, require_role, etc.
    """

    @staticmethod
    def check() -> FnSelector:
        """Common permission-check function names.

        Matches: ``has_permission``, ``check_permission``, ``can_access``,
        ``authorize``, ``is_authorized``.
        """
        return Fn.matching(
            r"^(has_permission|check_permission|can_access|authorize|is_authorized)$"
        )

    @staticmethod
    def require() -> FnSelector:
        """Common permission-require function names.

        Matches: ``require_permission``, ``require_role``,
        ``require_admin``, ``require_auth``.
        """
        return Fn.matching(r"^(require_permission|require_role|require_admin|require_auth)$")


class Str:
    """Selectors for string-normalization transforms.

    String normalizers canonicalize a string before it is compared, looked
    up, or stored -- lower-casing, case-folding, whitespace stripping, Unicode
    normalization.  They are central to *inconsistency* detection: when one part
    of a system normalizes a value (e.g. lowercases an email claim) and
    another part does not, the two interpret "the same" input differently,
    which is exactly the divergence these rules look for.

    Example::

        Str.normalize()  # any string-normalization transform
        Str.case_fold()  # .lower() / .casefold()
        Str.strip()  # .strip() / .lstrip() / .rstrip()
        Str.unicode_normalize()  # unicodedata.normalize(...)

    The ``str`` methods bind through a string *instance* (``email.lower()``)
    and therefore have no resolvable library FQN, so they are matched by short
    name -- the same heuristic name-pattern approach :meth:`Crypto.compare`
    and :meth:`Token.is_valid` use for instance-bound idioms.  The patterns
    are anchored (``^...$``) so partial names (``lowercase``, ``stripe``) do
    not match.  ``unicodedata.normalize`` is a module function and is matched
    by FQN.
    """

    @staticmethod
    def case_fold() -> FnSelector:
        """Case-normalization string methods.

        Matches the instance methods ``str.lower`` and ``str.casefold`` by
        short name (no resolvable FQN -- bound through a string instance).
        This is the email-claim-divergence transform: one code path
        lowercases an identifier while another does not.
        """
        return Fn.matching(r"^(lower|casefold)$")

    @staticmethod
    def strip() -> FnSelector:
        """Whitespace-stripping string methods.

        Matches ``str.strip`` / ``str.lstrip`` / ``str.rstrip`` by short name.
        """
        return Fn.matching(r"^(strip|lstrip|rstrip)$")

    @staticmethod
    def unicode_normalize() -> FnSelector:
        """Unicode normalization (NFC / NFKC / NFD / NFKD).

        Matches ``unicodedata.normalize`` by FQN.  Both the qualified
        ``unicodedata.normalize(...)`` call and the
        ``from unicodedata import normalize; normalize(...)`` form resolve to
        this FQN through L1 import resolution, so a name-pattern arm is
        unnecessary.  A bare ``normalize`` name is intentionally *not* matched:
        it is too generic (schema / path / model normalizers) and would
        over-broaden the selector.
        """
        return Fn.fqn("unicodedata.normalize")

    @staticmethod
    def normalize() -> FnSelector:
        """Any string-normalization transform.

        The union of :meth:`case_fold`, :meth:`strip`, and
        :meth:`unicode_normalize`.  Use this when a rule needs to know that
        *some* canonicalization occurred -- e.g. detecting normalization
        divergence between two code paths -- without caring which kind.
        """
        return Str.case_fold() | Str.strip() | Str.unicode_normalize()
