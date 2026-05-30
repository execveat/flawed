"""End-to-end tier.

A few well-chosen vertical-slice tests that drive the CLI as close to the real
entry point as possible (``CliRunner`` / ``--json`` / SARIF) and assert on the
rendered output. Kept intentionally small — broad empirical/corpus coverage is
out of scope for this tier. These exercise the full
L1+L2+L3 pipeline and so may spawn real tools (they live outside the unit tiers
for that reason).
"""
