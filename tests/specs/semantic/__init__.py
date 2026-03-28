"""Semantic API behavioral specifications.

These tests define the contract between provider declarations and
engine resolution.  They specify WHAT the Semantic API must detect,
organized by extension point and progressive complexity level.

Complexity levels:
  L0: Direct usage (literal FQN match)
  L1: Import aliasing (from X import Y as Z)
  L2: Variable assignment (v = request; v.args)
  L3: Cross-function same-file (helper() reads request.args)
  L4: Cross-file import (imported module reads request.args)
  L5: Subclass method (User(Model).save() inherits DB_WRITE)
  L6: Multi-level indirection (chains of L2-L4)
  L7: Dynamic patterns (expected to gracefully fail)

All tests are skipped until the Semantic Layer engine is implemented.
"""
