"""pyotp provider -- TOTP/HOTP two-factor authentication.

pyotp implements RFC 4226 (HOTP) and RFC 6238 (TOTP) one-time password
algorithms.

Security-relevant patterns:

- ``TOTP.verify()`` / ``HOTP.verify()`` are security checks that
  validate a user-supplied OTP code against the shared secret.
- ``TOTP.now()`` generates the current valid OTP (used server-side
  for comparison or display).
- ``random_base32()`` generates a shared secret for provisioning.
- ``provisioning_uri()`` generates the ``otpauth://`` URI for QR code
  enrollment.

FQNs verified against pyotp 2.9.0:
- ``pyotp.totp.TOTP`` (inherits from ``pyotp.otp.OTP``)
- ``pyotp.hotp.HOTP`` (inherits from ``pyotp.otp.OTP``)
- ``pyotp.random_base32`` (module-level in ``pyotp.__init__``)
"""

from __future__ import annotations

from flawed._semantic.providers._base import (
    CheckKind,
    FlowPropagatorPattern,
    Provider,
    ProviderMeta,
    SecurityCheckPattern,
)


class PyOTPProvider(Provider):
    meta = ProviderMeta(
        id="pyotp",
        name="pyotp",
        version="0.1.0",
        library="pyotp",
        library_fqn="pyotp",
    )

    # =================================================================
    # Security checks: OTP verification
    # =================================================================

    checks = (
        SecurityCheckPattern(
            fqn="pyotp.totp.TOTP.verify",
            kind=CheckKind.METHOD_CALL,
            category="TWO_FACTOR_VERIFY",
            description="Verify TOTP code against shared secret",
        ),
        SecurityCheckPattern(
            fqn="pyotp.hotp.HOTP.verify",
            kind=CheckKind.METHOD_CALL,
            category="TWO_FACTOR_VERIFY",
            description="Verify HOTP code against shared secret and counter",
        ),
        # random_base32 generates the shared secret -- treating it as
        # a security check in the KEY_GENERATION category
        SecurityCheckPattern(
            fqn="pyotp.random_base32",
            kind=CheckKind.CALL,
            category="KEY_GENERATION",
            description="Generate random base32 secret for OTP provisioning",
        ),
    )

    # =================================================================
    # Flow propagation
    # =================================================================

    propagators = (
        # The secret (arg 0 to TOTP.__init__) flows into now() output
        FlowPropagatorPattern(
            fqn="pyotp.totp.TOTP.now",
            input_arg=0,
            output="return",
            description="Secret-derived OTP flows from TOTP instance to OTP string",
        ),
        # provisioning_uri embeds the secret into the URI
        FlowPropagatorPattern(
            fqn="pyotp.totp.TOTP.provisioning_uri",
            input_arg=0,
            output="return",
            description="Account name flows into otpauth:// provisioning URI",
        ),
        FlowPropagatorPattern(
            fqn="pyotp.hotp.HOTP.provisioning_uri",
            input_arg=0,
            output="return",
            description="Account name flows into otpauth:// provisioning URI",
        ),
    )
