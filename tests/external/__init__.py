"""External-tool integration tier.

A deliberately small minority of tests that run REAL external tools
(basedpyright) by building an index live, each validating one
specific L1 build/extraction behavior that cannot be exercised from committed
artifacts. These are the only tests permitted to spawn a managed subprocess —
the enforcement guardrail fails any test outside this tier that does. They are
slow by nature; keep this tier minimal and intentional. Everything that merely
asserts facts over an already-built index belongs in ``tests/integration``
(loading committed artifacts), not here.
"""
